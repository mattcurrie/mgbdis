; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $01e", ROMX[$4000], BANK[$1e]

    ld a, [de]
    bit 3, a
    jr nz, jr_01e_401d

    bit 4, a
    jr nz, jr_01e_4023

    bit 5, a
    jr nz, jr_01e_402c

    bit 6, a
    jr nz, jr_01e_4035

    and $07
    ret z

    ld a, $c8
    ld [hl+], a
    ld a, $d1
    ld [hl+], a
    ld [hl], $d8
    ret


jr_01e_401d:
    ld a, $70
    ld [hl+], a
    ld [hl], $b8
    ret


jr_01e_4023:
    ld a, $d4
    ld [hl+], a
    ld a, $b9
    ld [hl+], a
    ld [hl], $70
    ret


jr_01e_402c:
    ld a, $ba
    ld [hl+], a
    ld a, $b5
    ld [hl+], a
    ld [hl], $d8
    ret


jr_01e_4035:
    ld a, $cf
    ld [hl+], a
    ld [hl], $cb
    ret


Call_01e_403b:
    ld a, [$d07c]
    add a
    add a
    ld hl, $405b
    ld e, a
    ld d, $00
    add hl, de
    ld a, [hl+]
    ld [$d05a], a
    ld a, [hl+]
    ld e, a
    ld a, [hl]
    ld d, a
    ld hl, $8310
    ld b, $1e
    ld a, [$d05a]
    ld c, a
    jp Jump_000_02dd


    ld c, a
    ld h, a
    ld b, b
    rst $38
    ld c, a
    ld d, a
    ld b, l
    rst $38
    ld b, b
    ld h, a
    ld b, b
    rst $38
    rrca
    rrca
    rra
    db $10
    ccf
    jr nz, jr_01e_40ed

    ld l, b
    cp a
    add sp, $7f
    ld h, b
    ccf
    ld hl, $417f
    add b
    add b
    ret nz

    ld b, b
    ldh [rNR41], a
    ld hl, sp+$38
    db $fc
    ld h, h
    db $fc
    add h
    cp $06
    rst $38
    dec b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    inc c
    rrca
    ld de, $111e
    ld e, $18
    jr jr_01e_40ce

    inc h
    ld h, d
    ld b, d
    pop de
    add c
    and c
    add c
    pop de
    add c
    xor e
    add c
    push de
    add c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr z, jr_01e_40b0

jr_01e_40b0:
    nop
    nop
    adc [hl]
    nop
    ccf
    jr nz, @+$61

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld c, $0e
    ld sp, $601f
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01e_40ce:
    nop
    rlca
    rlca
    jr jr_01e_40f2

    inc hl
    inc a
    inc hl
    inc a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add b
    add b
    ld h, b
    ldh [rNR10], a
    ldh a, [rNR10]
    ldh a, [rP1]
    nop
    nop
    nop
    nop
    nop

jr_01e_40ed:
    nop
    inc e
    nop
    ld a, $00

jr_01e_40f2:
    ld h, a
    nop
    ld l, a
    nop
    ld a, a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr c, jr_01e_4100

jr_01e_4100:
    ld a, h
    nop
    cp $00
    cp $00
    cp $03
    inc bc
    ld b, $05
    dec c
    ld a, [bc]
    ld a, [hl-]
    dec [hl]
    ld d, l
    ld l, d
    ld l, d
    ld d, l
    push de
    xor d
    ld [$00d5], a
    nop
    ldh [$e0], a
    ld d, b
    or b
    or b
    ld d, b
    ld e, b
    xor b
    xor h
    ld d, h
    ld d, [hl]
    xor d
    ld c, $f6
    nop
    nop
    nop
    nop
    ld bc, $0803
    add hl, de
    inc b
    dec c
    inc h
    ld l, h
    ld [de], a
    ld [hl], $12
    ld [hl], $10
    db $10
    ld c, b
    ld e, b
    inc h
    ld l, h
    sub d
    or [hl]
    sub d
    or [hl]
    ld c, c
    db $db
    ld c, c
    db $db
    ld c, c
    db $db
    rlca
    rlca
    rra
    rra
    ccf
    ccf
    ld [hl], e
    ld [hl], e
    ld h, c
    ld h, c
    ld [hl], e
    ld [hl], e
    ld a, a
    ld a, a
    dec a
    dec a
    rlca
    rlca
    ld h, l
    ld h, l
    ld a, b
    ld a, b
    ld c, $0e
    inc bc
    inc bc
    ld c, $0e
    ld a, b
    ld a, b
    ld h, b
    ld h, b
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ccf
    jr nz, jr_01e_41ad

    jr nz, @+$21

    jr jr_01e_4179

    rlca
    nop
    nop
    nop
    nop
    rst $38
    add hl, bc

jr_01e_4179:
    cp $f2
    db $fc
    inc b
    ld hl, sp+$08
    ldh a, [$30]
    ret c

    ret c

    jr nc, jr_01e_41b5

    ld h, b
    ld h, b
    jr nz, jr_01e_41c8

    jr nz, jr_01e_41ca

    jr c, @+$29

    ccf
    jr nz, jr_01e_41af

    db $10
    rra
    db $10
    rrca
    inc c
    inc bc
    inc bc
    db $eb
    add c
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
    add c
    pop af
    ld b, d
    ld [hl], d
    inc h
    inc [hl]
    jr @+$1a

    dec sp
    ld b, h
    ld c, $f1
    ld b, b
    cp a

jr_01e_41ad:
    ld h, [hl]
    sbc c

jr_01e_41af:
    ld a, a
    add b
    dec sp
    call nz, $7f00

jr_01e_41b5:
    nop
    inc sp
    inc b
    ld a, e
    ld [hl], c
    adc [hl]
    ccf
    ret nz

    add hl, de
    and $00
    rst $38
    ld b, h
    cp e
    inc sp
    ld c, h
    nop
    inc sp
    ld b, b

jr_01e_41c8:
    ld a, a
    ld b, b

jr_01e_41ca:
    ld a, a
    ld b, b
    ld a, a
    ld b, c
    ld a, [hl]
    ccf
    jr nz, jr_01e_4211

    jr nz, jr_01e_41f3

    jr jr_01e_41dd

    rlca
    ld [$18f8], sp
    add sp, $38
    ret z

jr_01e_41dd:
    ld hl, sp+$08
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh [$60], a
    add b
    add b
    nop
    ld a, a
    nop
    ccf
    nop
    ccf
    nop
    rra
    nop
    rrca
    nop
    rlca

jr_01e_41f3:
    nop
    inc bc
    nop
    ld bc, $fe00
    nop
    db $fc
    nop
    db $fc
    nop
    ld hl, sp+$00
    ldh a, [rP1]
    ldh [rP1], a
    ret nz

    nop
    add b
    or h
    db $eb
    sbc [hl]
    rst $38
    sub l
    rst $38
    xor d
    rst $38
    ld d, l
    ld a, a

jr_01e_4211:
    ld a, [hl+]
    ccf
    dec e
    rra
    rlca
    rlca
    rrca
    ld sp, hl
    rra
    pop af
    rst $38
    pop hl
    cp [hl]
    ld a, [c]
    ld e, [hl]
    ld a, [$fcac]
    ld [hl], b
    ldh a, [$c0]
    ret nz

    nop
    nop
    ld [$2a00], sp
    nop
    inc e
    nop
    ld a, a
    nop
    inc e
    nop
    ld a, [hl+]
    nop
    ld [$0300], sp
    nop
    inc c
    nop
    jr nc, jr_01e_423d

jr_01e_423d:
    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp a
    cp a

jr_01e_4249:
    ld c, $31
    ld b, a
    ld a, b
    adc a
    ldh a, [rSC]
    db $fd
    ld b, a
    ld a, c
    add [hl]
    cp $38

jr_01e_4256:
    jr c, jr_01e_4256

    cp $e1
    ld de, $8e76
    ld a, b
    sbc b
    ldh [$60], a
    add b
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0201
    ld bc, $0302
    inc e
    dec e
    ld [hl+], a
    rra
    jr nz, jr_01e_42b4

    ld b, c
    nop
    nop
    nop
    ldh a, [$f0]
    ld [$07f8], sp
    db $fd
    ld [bc], a
    ldh a, [rIF]
    ldh [rNR34], a
    ld b, b
    cp h
    jr nz, jr_01e_4249

    ld b, b
    add b
    add b
    nop
    nop
    nop
    ld a, b
    nop
    rst $00
    jr c, jr_01e_42cc

    rst $38
    rst $00
    rst $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, $06
    add hl, sp
    ccf
    ld b, b
    nop
    nop
    nop
    ld bc, $0601
    rlca
    ld [$110e], sp
    ld e, $21
    inc e

jr_01e_42b4:
    ld [hl+], a
    jr nc, jr_01e_4303

    nop
    ld [hl], b
    ld [hl], b
    adc h
    ldh a, [$0e]
    add b
    ld a, h
    nop
    ret nz

    nop
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01e_42cc:
    nop
    nop
    ld bc, $0600
    nop
    ld [$3000], sp
    nop
    ret nz

    nop
    inc bc
    nop
    inc b
    nop
    ld [$b000], sp
    nop
    ld b, b
    nop
    nop
    nop
    nop
    nop
    nop
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
    ld bc, $181a
    dec h
    nop
    ld bc, $0201
    ld bc, $0002
    ld bc, $6000
    ld h, b
    sub b

jr_01e_4303:
    ld h, b
    sub b
    nop
    ld h, b
    rrca
    rrca
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, h
    ld a, h
    ld a, b
    ld a, b
    jr nc, jr_01e_4343

    nop
    nop
    ld bc, $f001
    ldh a, [$fc]
    db $fc
    cp $fe
    ccf
    ccf
    rra
    rra
    rra
    rra
    ld a, $3e
    db $fc
    db $fc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_01e_4338

    ld d, $06
    add hl, bc
    rlca
    ld [$0403], sp
    nop

jr_01e_4338:
    jr jr_01e_4352

    inc h
    jr @+$26

    inc a
    ld b, d
    inc a
    ld b, d
    ld a, [hl]

jr_01e_4342:
    add c

jr_01e_4343:
    rst $38
    nop
    rst $38
    nop
    nop
    nop
    nop
    ld bc, $0700
    inc bc
    inc c
    ld b, $19
    inc c

jr_01e_4352:
    ld [hl-], a
    jr jr_01e_4379

    db $10
    ld l, b
    nop
    inc a
    jr jr_01e_4342

    rst $38
    nop
    jp Jump_000_003c


    jp RST_00


    nop
    nop
    nop
    nop
    ld a, $41
    inc e
    ld h, e
    nop
    ld a, a
    nop
    ld a, a
    nop
    ccf
    nop
    rra
    nop
    rra
    nop
    inc e
    nop
    db $fc

jr_01e_4379:
    nop
    db $fc
    nop
    ld hl, sp+$00
    ldh [rP1], a
    ldh [rP1], a
    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0201
    ld bc, $0102
    ld [bc], a
    inc bc
    inc b
    inc bc
    inc b
    ld bc, $7f02
    add b
    cp $01
    ld hl, sp+$07
    ld hl, sp+$07
    ldh a, [$0e]
    ret nz

    ld a, $c0
    inc a
    add b
    ld [hl], b
    jr nc, @+$4e

    ld h, b
    sbc b
    ld h, b
    sbc b
    ld h, b
    sub b
    nop
    ld [hl], b
    nop
    ld h, b
    nop
    jr nz, jr_01e_43b6

jr_01e_43b6:
    nop
    ld b, b
    ld b, b
    call nz, $fcc4
    db $fc
    inc a
    inc a
    rlca
    rlca
    ld b, $06
    inc c
    inc c
    jr c, jr_01e_43ff

    nop
    nop
    nop
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
    ld [$0806], sp
    nop
    ld [$1408], sp
    ld [$1c14], sp
    ld [hl+], a
    ld a, $41
    ld [hl], $41
    inc e
    ld [hl+], a
    nop
    inc e
    jr @+$26

    nop
    jr jr_01e_43ec

jr_01e_43ec:
    rlca
    rlca
    jr jr_01e_440f

    jr nz, jr_01e_4411

    jr nz, jr_01e_43fb

    jr jr_01e_43f6

jr_01e_43f6:
    rlca
    nop
    nop
    nop
    nop

jr_01e_43fb:
    nop
    nop
    nop
    rlca

jr_01e_43ff:
    rlca
    jr c, jr_01e_443a

    ld b, b
    rlca
    jr c, jr_01e_4406

jr_01e_4406:
    rlca
    inc bc
    inc bc
    inc bc
    inc bc
    ld bc, $0001
    nop

jr_01e_440f:
    inc bc
    inc bc

jr_01e_4411:
    rlca
    rlca
    rlca
    rlca
    inc bc
    inc bc
    ldh a, [$f0]
    ret nz

    ret nz

    add b
    add b

jr_01e_441d:
    nop
    nop
    ret nz

    ret nz

    ldh [$e0], a

jr_01e_4423:
    ldh [$e0], a
    ret nz

    ret nz

    inc bc
    inc b
    rlca
    jr jr_01e_444b

    ld h, b
    ld a, a
    add b
    ld a, a
    add b
    rra
    ld h, b
    daa
    jr c, jr_01e_4439

    inc b
    rst $38
    nop

jr_01e_4439:
    rst $38

jr_01e_443a:
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
    jr nc, jr_01e_4491

    jr nc, jr_01e_4493

jr_01e_444b:
    jr nz, jr_01e_441d

    ld h, b
    sub b
    ld h, b
    sub b
    jr nz, jr_01e_4423

    jr nc, @+$4a

    jr nc, jr_01e_449f

    ld [hl], b
    ld [hl], b
    rrca
    rrca
    inc bc
    inc bc
    inc e
    inc e
    jr c, jr_01e_4499

    ret nz

    ret nz

    ldh a, [$f0]
    inc e
    inc e
    nop
    nop
    ld b, b
    ld b, b
    ld [c], a
    and d
    ld b, [hl]
    ld b, [hl]
    ld c, $0a
    ld e, $12
    ld e, $12
    inc c
    inc c
    nop
    rst $38
    ld e, d
    and l
    ld a, [hl]
    add c
    inc h
    db $db
    nop
    rst $38
    ld e, d
    and l
    ld a, [hl]
    add c
    inc h
    db $db
    ld a, [hl]
    add c
    inc h
    db $db
    nop
    rst $38
    ld e, d
    and l
    ld a, [hl]
    add c

jr_01e_4491:
    inc h
    db $db

jr_01e_4493:
    nop
    rst $38
    ld e, d
    and l
    rlca
    rlca

jr_01e_4499:
    jr jr_01e_44ba

    daa
    jr c, @+$5a

    ld h, b

jr_01e_449f:
    ld d, b
    ld h, b
    and b
    ret nz

    and b
    ret nz

    and b
    ret nz

    nop
    ld bc, $4100
    ld bc, $1332
    inc l
    rrca
    db $10
    rrca
    db $10
    rra
    jr nz, jr_01e_44f5

    ret nz

    inc a
    ret nz

    di

jr_01e_44ba:
    nop
    rst $08
    nop
    inc a
    inc bc
    di
    rrca
    call z, $303c
    ldh a, [$c0]
    ret nz

    di
    rrca
    call z, $303c
    ldh a, [$c0]
    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc b
    rlca
    ld [$110e], sp
    inc e
    ld [hl+], a
    jr c, jr_01e_4525

    ld [hl], b
    adc b
    ldh [rNR10], a
    ret nz

    jr nz, jr_01e_44e8

jr_01e_44e8:
    nop
    nop
    nop
    inc bc
    inc bc
    inc b
    rlca
    ld [$100f], sp
    rra
    db $10
    rra

jr_01e_44f5:
    jr nz, @+$41

    inc a
    inc a
    ld c, [hl]
    ld b, d
    add l
    add e
    add l
    add e
    call $f983
    add a
    ld b, d
    ld a, [hl]
    inc a
    inc a

jr_01e_4507:
    nop
    nop
    nop
    nop
    nop
    nop
    ld e, $1e
    ld hl, $203f
    ccf
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    nop
    nop
    nop
    nop
    nop
    nop
    ld e, $1e
    daa
    add hl, sp
    inc h
    dec sp
    ld c, l
    ld [hl], d

jr_01e_4525:
    ld c, c
    halt
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add b
    add b
    ldh [$60], a
    or b
    ld d, b
    jr nc, jr_01e_4507

    inc a
    inc a
    ld b, d
    ld a, [hl]
    pop bc
    rst $38
    db $e3
    cp a
    push af
    sbc a
    ld a, e
    ld c, l
    ld a, [hl]
    ld c, d
    inc a
    inc a
    jr c, jr_01e_4581

    rra
    rla
    ld l, a
    ld [hl], c
    ld a, [c]
    ld e, $ff
    add c
    ld a, a
    ld b, c
    ld a, a
    ld h, e
    inc a
    inc a
    ret nz

    ret nz

    ldh [$a0], a
    ldh [$a0], a
    ldh a, [$90]
    ld hl, sp-$78
    cp h
    add h
    ld e, [hl]
    ld b, d
    ld c, a
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
    jr jr_01e_458d

    inc [hl]
    inc l
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc

jr_01e_4581:
    inc c
    rrca
    db $10
    rra
    db $10
    rra
    ld bc, $0301
    ld [bc], a
    inc bc
    ld [bc], a

jr_01e_458d:
    rlca
    inc b
    rst $38
    db $fc
    rst $38
    add b
    ld a, a
    ld b, b
    ccf
    jr nz, jr_01e_4598

jr_01e_4598:
    ld [$1d00], sp
    nop
    ld e, a
    nop
    rst $38
    nop
    rst $38
    nop
    ld a, a
    nop
    ld a, a
    ld [bc], a
    dec a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0300
    nop
    nop
    inc a
    inc a
    ld a, [hl]
    ld b, d
    rst $00
    cp c
    ei
    add l
    ld a, h
    ld b, e
    ccf
    ld sp, $0f0f
    nop
    add c
    add c
    ld b, d
    add c
    ld b, d
    jp $6624


    sbc c
    inc h
    db $db
    inc a
    jp Jump_01e_6618


    nop
    nop
    nop
    nop
    inc de
    inc de
    ccf
    ccf
    rra
    rra
    jr jr_01e_45fb

    rrca
    rrca
    ld [$0008], sp
    nop
    jr c, jr_01e_4623

    ld hl, sp-$08
    add sp, -$18
    adc b
    adc b
    ld a, b
    ld a, b
    add h
    add h
    inc b
    inc b
    inc bc
    inc bc
    rrca
    inc c

jr_01e_45fb:
    ccf
    jr nc, jr_01e_467d

    ld d, c
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    ld a, a
    ld b, b
    add b
    add b
    ldh [$60], a
    ldh a, [$f0]
    ld hl, sp+$08
    db $fc
    inc b
    cp $02
    cp $02
    cp $02
    ld bc, $0102
    ld [bc], a
    ld bc, $0102
    ld [bc], a
    ld bc, $0302
    inc b

jr_01e_4623:
    ld b, $19
    inc e
    ld [hl+], a
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    nop
    add b
    nop
    nop
    nop
    nop
    nop
    ccf
    ld a, $41
    ld b, c
    cp [hl]
    ld [$04f5], sp
    dec bc
    nop
    rlca
    rlca
    ld [$0000], sp
    nop
    nop
    nop
    add b
    nop
    ret nz

    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    nop
    add b
    daa
    jr nz, jr_01e_466d

    db $10
    inc c
    inc c
    inc bc
    inc bc
    nop
    nop
    ld bc, $0101
    ld bc, $0000
    and h
    cp h
    add sp, $78
    add sp, $38

jr_01e_466d:
    ret c

    ld a, b
    sub $fe
    ld sp, $a9ff
    ld l, a
    add $c6
    jr nz, jr_01e_46b8

    jr nz, jr_01e_46ba

    jr nc, jr_01e_46bc

jr_01e_467d:
    jr nc, jr_01e_46be

    inc e
    rra
    rra
    rra
    rrca
    rrca
    inc bc
    inc bc
    rra
    db $10
    rra
    db $10
    ccf
    jr nz, jr_01e_46cd

    jr nz, jr_01e_470f

    ld b, c
    ld a, [hl]
    ld b, [hl]
    ld hl, sp-$68
    ldh [$e0], a
    inc bc
    db $fc
    inc bc
    db $fc
    rlca
    ld hl, sp+$07
    ld a, b
    rlca
    ld a, b
    rlca
    jr c, jr_01e_46a7

    inc a
    inc bc
    inc e

jr_01e_46a7:
    nop
    rlca
    nop
    rlca
    nop
    rra
    ld bc, $033e
    inc a
    inc bc
    inc e

jr_01e_46b3:
    inc bc
    inc e
    ld bc, $020e

jr_01e_46b8:
    inc bc
    ld [bc], a

jr_01e_46ba:
    inc bc
    dec b

jr_01e_46bc:
    rlca
    dec b

jr_01e_46be:
    rlca
    ld [$080f], sp
    rrca
    inc b
    rlca
    inc bc
    inc bc
    ld b, b
    ret nz

    add b
    add b
    nop
    nop

jr_01e_46cd:
    nop
    nop
    ret nz

    ret nz

    jr nz, jr_01e_46b3

    db $10
    ldh a, [$f0]
    ldh a, [$0c]
    inc c
    inc b
    inc b
    ld [$3808], sp
    jr c, jr_01e_4758

    ld a, b
    ld a, b
    ld a, b
    jr nc, @+$32

    nop
    nop
    ld [$0808], sp
    ld [$1c1c], sp
    inc a
    inc a
    inc a
    inc a
    jr jr_01e_470b

    nop
    nop
    nop
    nop
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    cp a
    ret nz

    ld c, [hl]
    ld [hl], c
    ld b, b
    ld a, a
    jr nc, jr_01e_4744

    rrca
    rrca
    db $fc
    inc b
    cp $02

jr_01e_470b:
    ld a, [$a246]
    ld a, [hl]

jr_01e_470f:
    inc h
    db $fc
    ld e, b
    ld hl, sp-$20
    ldh [rP1], a
    nop
    jr nc, jr_01e_4768

    ccf
    ld b, b
    ld bc, $013e
    ld [bc], a
    ld bc, $0102
    ld [bc], a
    ld bc, $0102
    ld [bc], a
    nop
    add b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    add b
    ld b, b
    inc b
    dec bc
    inc b
    ld a, [bc]
    inc b
    ld a, [bc]
    inc b
    ld a, [bc]
    ld [bc], a
    dec b
    ld bc, $0002

jr_01e_4744:
    ld bc, $0000
    add b
    ld b, b
    ld b, b
    or b
    jr nc, jr_01e_4795

    ld a, b
    add h
    sbc h
    ld h, d
    ld c, $91
    ld b, $89
    nop
    ld b, $00

jr_01e_4758:
    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_01e_4768

    ld d, $06
    add hl, bc
    rlca
    ld [$0403], sp
    nop

jr_01e_4768:
    ld bc, $0100
    ld bc, $0102
    ld [bc], a
    inc bc
    inc b
    rlca
    adc b
    adc a
    ld [hl], b
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    rra
    rrca
    rrca
    ccf
    ccf
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

jr_01e_4795:
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0301
    inc bc
    rlca
    rlca
    rrca
    rrca
    ld e, $1f
    rlca
    rlca
    ccf
    ccf
    ld a, a
    ld a, a
    db $fc
    rst $38
    ldh [rIE], a
    jp $0ffc


    ldh a, [$3e]
    ret nz

    nop
    nop
    nop
    nop
    inc bc
    inc bc
    rra
    jr jr_01e_47f8

    daa
    ld h, b
    ld e, b
    ret nz

    and a
    add a
    ret c

    nop
    nop
    ld [hl], b
    ld [hl], b
    cp $06
    ld [bc], a
    db $fc
    ld bc, $0103
    db $fd
    ld a, [hl]
    add d
    sbc h
    ld a, b
    nop
    ld b, c
    ld b, $37
    ld [$100e], sp
    add hl, de
    db $10
    ld d, $0c
    dec c
    inc bc
    ld [$0607], sp
    call nz, Call_000_02fc
    adc [hl]
    ld [bc], a
    ld [hl], d
    db $f4
    inc c

jr_01e_47ef:
    ld a, [de]
    ld a, [de]
    ld a, d
    ld [c], a
    db $f4
    inc c
    jr jr_01e_47ef

    nop

jr_01e_47f8:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0301
    inc bc
    nop
    nop
    ld bc, $1c01
    inc e
    ccf
    ccf
    ld a, h
    ld a, h
    ld hl, sp-$08
    ldh [$e0], a

jr_01e_4811:
    ld hl, sp-$08

jr_01e_4813:
    db $fc
    db $fc

jr_01e_4815:
    ldh [$e0], a

jr_01e_4817:
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01e_481e:
    nop
    nop
    ld [de], a
    ld [de], a
    dec l
    dec d
    ld a, [hl+]
    dec sp
    call nz, $b040
    ldh a, [$08]
    xor b
    ld d, h
    ld d, h
    xor d
    ld hl, sp+$04
    db $f4
    ld a, [bc]
    ld hl, sp+$04
    ldh [rNR23], a
    nop
    rst $38
    nop
    rst $38
    ccf
    ret nz

    jr nz, jr_01e_481e

    jr nz, jr_01e_4811

    jr nz, jr_01e_4813

    jr nz, jr_01e_4815

    jr nz, jr_01e_4817

    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
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
    inc bc
    inc b
    ld bc, $0102
    ld [bc], a
    ld bc, $0302
    inc b
    rlca
    ld [$300f], sp
    ccf
    ret nz

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
    ccf
    ccf
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rlca
    rlca
    rra
    rra
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    inc a
    ccf
    inc a
    ccf
    ld a, c
    ld a, [hl]
    ld [hl], c
    ld a, [hl]
    ld [hl], e
    ld a, h
    di
    db $fc
    rst $20
    ld hl, sp-$1a
    ld hl, sp+$78
    add b
    ldh [rP1], a
    ret nz

    nop
    add b
    nop
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, [hl]
    ld h, c
    rst $28
    sbc [hl]
    adc [hl]
    sub b
    ld b, b
    ld h, c
    dec l
    ld e, $42
    ld c, h
    jr nz, jr_01e_48f6

    ld b, $0f
    ld a, [c]
    ld [$6684], a
    jr jr_01e_48e7

    call c, $f0e4
    ld a, [bc]
    db $10
    ld de, $e1c0
    jr c, jr_01e_490f

    add hl, bc
    add hl, bc
    dec bc
    ld [$050e], sp

jr_01e_48dd:
    inc de
    rra
    nop
    add hl, bc
    ld de, $0e16
    add hl, bc
    inc bc
    inc bc

jr_01e_48e7:
    db $e4
    db $e4
    add sp, $08
    jr nc, jr_01e_48dd

    ret z

    ldh a, [$08]
    ret z

    ret z

    jr nc, jr_01e_4924

    ldh a, [$c0]

jr_01e_48f6:
    ret nz

    inc bc
    inc bc
    ld c, $0e
    jr c, jr_01e_4935

    ld a, a
    ld a, a
    rra
    rra
    inc c
    inc c
    jr nc, jr_01e_4935

    ld b, b
    ld b, b
    rrca
    rrca

jr_01e_4909:
    ccf
    ccf

jr_01e_490b:
    rst $38
    rst $38

jr_01e_490d:
    rst $00
    rst $38

jr_01e_490f:
    add e
    rst $00

jr_01e_4911:
    add e
    rst $00

jr_01e_4913:
    add e
    rst $00

jr_01e_4915:
    rst $00
    rst $38

jr_01e_4917:
    nop
    ld hl, $5720
    ld [hl+], a
    ld e, l
    dec [hl]
    jp z, $d42b

    rst $10
    jr z, @+$01

jr_01e_4924:
    nop
    rst $38
    nop
    nop
    nop
    ld e, $1e
    ld a, $22
    ld a, d
    ld b, [hl]
    ld [hl], d
    ld c, [hl]
    ld h, h
    ld e, h
    ld a, b
    ld a, b

jr_01e_4935:
    nop
    nop
    jr nz, jr_01e_4909

    jr nz, jr_01e_490b

    jr nz, jr_01e_490d

    jr nz, jr_01e_490f

    jr nz, jr_01e_4911

    jr nz, jr_01e_4913

    jr nz, jr_01e_4915

    jr nz, jr_01e_4917

    nop
    inc a
    nop
    inc a
    nop
    jr jr_01e_494e

jr_01e_494e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01e_4958:
    ld bc, $0f00
    nop
    ccf
    nop
    ld a, $00
    ld a, [hl]
    nop
    ld c, [hl]
    nop
    inc e
    nop
    nop
    nop
    jr z, jr_01e_496a

jr_01e_496a:
    ld a, [hl+]
    nop
    ld l, [hl]
    nop
    ld a, [hl]
    jr jr_01e_4958

    inc a
    jp $c33c


    inc a
    ld b, d
    nop
    nop
    nop
    stop
    inc d
    nop
    inc a
    nop
    ld a, [hl]
    jr jr_01e_49e9

    jr jr_01e_49eb

    jr jr_01e_49ab

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
    ld bc, $0301
    inc bc
    dec de
    dec de
    ccf
    ccf
    ccf
    ccf
    rra
    rra
    ld a, a
    ld a, a
    rst $38
    rst $38
    db $10
    db $10
    jr c, jr_01e_49e3

jr_01e_49ab:
    jr c, jr_01e_49e5

    ld a, h
    ld c, h
    ld c, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    jr c, jr_01e_49ef

    ld h, h
    inc e
    ld h, h
    inc e
    ld [hl-], a
    ld c, $32
    ld c, $32
    ld c, $19
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    ld [hl-], a
    ld c, $32
    ld c, $32
    ld c, $19
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca
    add hl, de
    rlca

jr_01e_49e3:
    add hl, de
    rlca

jr_01e_49e5:
    add hl, de
    rlca
    rst $38
    rst $38

jr_01e_49e9:
    rst $38
    rst $38

jr_01e_49eb:
    rst $38
    rst $38
    rst $38
    rst $38

jr_01e_49ef:
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rrca
    nop
    ld a, $00
    db $fc
    nop
    ld h, b
    nop
    jr c, jr_01e_4a01

jr_01e_4a01:
    inc a
    nop
    inc a
    nop
    ldh a, [rP1]
    ld h, b
    nop
    ld a, h
    nop
    ccf
    nop
    sub e
    nop
    reti


    nop
    db $fc
    nop
    ld a, [hl]
    nop
    nop
    nop
    jr nc, jr_01e_4a19

jr_01e_4a19:
    ld [hl-], a
    nop
    halt
    ld a, a
    nop
    ld [hl], e
    nop
    ld h, a
    nop
    inc l
    nop
    inc c
    nop
    nop
    ccf
    nop
    ld a, a
    rra
    ld h, b
    ld [$0877], sp
    ld [hl], $04
    ld a, [hl-]
    ld b, $19
    ld [bc], a
    dec c
    ld bc, $010e
    ld b, $00
    rlca
    nop
    inc bc
    nop
    ld bc, $0100
    nop
    nop
    nop
    nop
    inc b
    rlca
    ld [$080f], sp
    rrca
    db $10
    rra
    db $10
    rra
    rra
    rra
    nop
    nop
    nop
    nop
    ld [$08f8], sp
    ld hl, sp+$10
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [$f0]
    ldh a, [rP1]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld l, a
    ld l, a
    ld d, b
    ld a, a
    ld b, b
    ld a, a
    ld e, b
    ld a, a
    ld d, a
    ld [hl], a
    ld h, e
    ld h, e
    nop
    nop
    nop
    nop
    adc $ce
    ld [hl-], a
    cp $02
    cp $12
    cp $e4
    db $fc
    inc b
    db $fc
    call nc, $cdd4
    call $ffff
    nop
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, [hl]
    ld d, [hl]
    ld d, [hl]
    ld d, [hl]
    cp $fe
    nop
    cp $fe
    cp $00
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
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    adc $ce
    push de
    push de
    call Call_000_00cd
    nop
    nop
    nop
    cp $fe
    nop
    cp $fe
    cp $ce
    adc $56
    ld d, [hl]
    ld c, [hl]
    ld c, [hl]
    dec h
    ccf
    ld b, b
    ld l, a
    ld b, b
    ld l, a
    ld b, b
    ld a, a
    ld hl, $1e3f
    ld e, $00
    nop
    nop
    nop
    sub h
    db $fc
    add d
    cp [hl]
    add d
    cp [hl]
    add d
    cp $84
    db $fc
    ld a, b
    ld a, b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $3601
    ld [hl], $28
    jr z, @+$15

    inc de
    inc c
    inc c
    dec de
    dec de
    nop
    nop
    nop
    nop
    call c, Call_000_34dc
    inc [hl]
    db $e4
    db $e4
    ld a, [bc]
    ld a, [bc]
    ld [$6aea], a
    ld l, d
    ld a, [hl+]
    dec sp
    ld h, $27
    db $10
    db $10
    db $10
    db $10
    inc c
    inc c
    inc bc
    inc bc
    nop
    nop
    nop
    nop
    ld d, h
    call c, $e464
    ld [$0808], sp
    ld [$3030], sp
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop

jr_01e_4b28:
    nop
    nop
    nop
    inc bc
    inc bc
    inc c
    rrca

jr_01e_4b2f:
    db $10
    ld e, $10
    ld e, $2c
    ccf
    ld a, [hl+]
    dec sp
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    jr nc, jr_01e_4b2f

    ld [$0878], sp
    ld a, b
    inc [hl]
    db $fc
    ld d, h
    call c, $2020
    add hl, hl
    add hl, hl
    db $10
    db $10
    inc e
    inc e
    inc de
    inc de
    ld c, $0e
    nop
    nop
    nop
    nop
    inc b
    inc b
    sub h
    sub h
    ld [$3808], sp
    jr c, jr_01e_4b28

    ret z

    ld [hl], b
    ld [hl], b
    nop
    nop
    nop
    nop
    nop
    nop
    inc c
    inc c
    inc de
    rra
    ld [de], a
    ld a, [de]
    db $10
    ld de, $1818
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    nop
    nop
    jr nc, jr_01e_4bab

    ret z

    ld hl, sp+$48
    ld e, b
    ld [$1888], sp
    jr @+$4a

    ld c, b
    ld c, b
    ld c, b
    ld a, b
    ld a, d
    ld a, h
    ld a, [hl]
    ccf
    ccf
    rra
    rra
    rra
    rra
    inc c
    inc c
    nop
    nop
    nop
    nop
    ld e, $5e
    ld a, $7e
    db $fc
    db $fc
    ld hl, sp-$08
    ld hl, sp-$08
    jr nc, @+$32

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01e_4bab:
    ld [hl-], a
    ld [hl-], a
    ccf
    ccf
    ccf
    ccf
    dec de
    dec de
    add hl, sp
    add hl, sp
    ccf
    ccf
    nop
    nop
    nop
    nop
    ld c, h
    ld c, h
    db $fc
    db $fc
    db $fc
    db $fc
    ret c

    ret c

    sbc h
    sbc h
    db $fc
    db $fc

Call_01e_4bc7:
    ld l, c
    ld h, b
    ld a, [hl+]
    ld [$d066], a
    ld a, [$d07a]
    ld e, a
    ld a, [$d079]
    ld d, a
    xor a
    ld [$d061], a

Jump_01e_4bd9:
    ld a, [$d061]
    inc a
    ld [$d061], a
    ld a, [$d068]
    dec a
    jr z, jr_01e_4c1a

    dec a
    jp z, Jump_01e_4c4f

    dec a
    jr z, jr_01e_4bf9

    ld a, [$d05f]
    add [hl]
    ld [de], a
    inc hl
    inc de
    ld a, [$d05e]
    jr jr_01e_4c0b

jr_01e_4bf9:
    ld a, [$d05f]
    ld b, a
    ld a, $88
    sub b
    add [hl]
    ld [de], a
    inc hl
    inc de
    ld a, [$d05e]
    ld b, a
    ld a, $a8
    sub b

jr_01e_4c0b:
    add [hl]
    ld [de], a
    inc hl
    inc de
    ld a, [hl+]
    add $31
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    jp Jump_01e_4c75


jr_01e_4c1a:
    ld a, [$d05f]
    add [hl]
    ld b, a
    ld a, $88
    sub b
    ld [de], a
    inc hl
    inc de
    ld a, [$d05e]
    add [hl]
    ld b, a
    ld a, $a8
    sub b
    ld [de], a
    inc hl
    inc de
    ld a, [hl+]
    add $31
    ld [de], a
    inc de
    ld a, [hl+]
    and a
    ld b, $60
    jr z, jr_01e_4c49

    cp $20
    ld b, $40
    jr z, jr_01e_4c49

    cp $40
    ld b, $20
    jr z, jr_01e_4c49

    ld b, $00

jr_01e_4c49:
    ld a, b
    ld [de], a
    inc de
    jp Jump_01e_4c75


Jump_01e_4c4f:
    ld a, [$d05f]
    add [hl]
    add $28
    ld [de], a
    inc hl
    inc de
    ld a, [$d05e]
    add [hl]
    ld b, a
    ld a, $a8
    sub b
    ld [de], a
    inc hl
    inc de
    ld a, [hl+]
    add $31
    ld [de], a
    inc de
    ld a, [hl+]
    bit 5, a
    jr nz, jr_01e_4c71

    set 5, a
    jr jr_01e_4c73

jr_01e_4c71:
    res 5, a

jr_01e_4c73:
    ld [de], a
    inc de

Jump_01e_4c75:
    ld a, [$d061]
    ld c, a
    ld a, [$d066]
    cp c
    jp nz, Jump_01e_4bd9

    ld a, [$d07b]
    cp $02
    jr z, jr_01e_4caf

    ld a, [$d063]
    ld c, a
    call Call_000_3781
    ld a, [$d07b]
    cp $03
    jr z, jr_01e_4caf

    cp $04
    jr z, jr_01e_4cb7

    ld a, [$d059]
    cp $2d
    jr z, jr_01e_4ca3

    call Call_01e_4f03

jr_01e_4ca3:
    ld hl, $c300
    ld a, l
    ld [$d07a], a
    ld a, h
    ld [$d079], a
    ret


jr_01e_4caf:
    ld a, e
    ld [$d07a], a
    ld a, d
    ld [$d079], a

jr_01e_4cb7:
    ret


Call_01e_4cb8:
Jump_01e_4cb8:
    xor a
    ldh [$8b], a
    ld [$d068], a
    ld a, [$d059]
    dec a
    ld l, a
    ld h, $00
    add hl, hl
    ld de, $60a9
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_01e_4ccd:
    ld a, [hl+]
    cp $ff
    jr z, jr_01e_4d42

    cp $c0
    jr c, jr_01e_4d01

    ld c, a
    ld de, $510d

jr_01e_4cda:
    ld a, [de]
    cp c
    jr z, jr_01e_4ce3

    inc de
    inc de
    inc de
    jr jr_01e_4cda

jr_01e_4ce3:
    ld a, [hl+]
    cp $ff
    jr z, jr_01e_4cf5

    ld [$cf02], a
    push hl
    push de
    call Call_01e_58a6
    call Call_000_0e45
    pop de
    pop hl

jr_01e_4cf5:
    push hl
    inc de
    ld a, [de]
    ld l, a
    inc de
    ld a, [de]
    ld h, a
    ld de, $4d3f
    push de
    jp hl


jr_01e_4d01:
    ld c, a
    and $3f
    ld [$d063], a
    xor a
    sla c
    rla
    sla c
    rla
    ld [$d07c], a
    ld a, [hl+]
    ld [$cf02], a
    ld a, [hl+]
    ld c, l
    ld b, h
    ld l, a
    ld h, $00
    add hl, hl
    ld de, $6799
    add hl, de
    ld a, l
    ld [$d071], a
    ld a, h
    ld [$d072], a
    ld l, c
    ld h, b
    push hl
    ldh a, [rOBP0]
    push af
    ld a, [$cc79]
    ldh [rOBP0], a
    call Call_01e_403b
    call Call_01e_4d43
    call Call_01e_4e8e
    pop af
    ldh [rOBP0], a
    pop hl
    jr jr_01e_4ccd

jr_01e_4d42:
    ret


Call_01e_4d43:
    ld a, [$d072]
    ld h, a
    ld a, [$d071]
    ld l, a
    ld a, [hl+]
    ld e, a
    ld a, [hl]
    ld d, a
    ld a, [de]
    ld b, a
    and $1f
    ld [$d064], a
    ld a, b
    and $e0
    cp $a0
    jr nz, jr_01e_4d62

    call Call_01e_4d91
    jr jr_01e_4d65

jr_01e_4d62:
    call Call_01e_4d89

jr_01e_4d65:
    srl a
    swap a
    ld [$d068], a
    cp $04
    ld hl, $0000
    jr nz, jr_01e_4d7e

    ld a, [$d064]
    dec a
    ld bc, $0003

jr_01e_4d7a:
    add hl, bc
    dec a
    jr nz, jr_01e_4d7a

jr_01e_4d7e:
    inc de
    add hl, de
    ld a, l
    ld [$d073], a
    ld a, h
    ld [$d074], a
    ret


Call_01e_4d89:
    ld b, a
    ldh a, [$f3]
    and a
    ld a, b
    ret nz

    xor a
    ret


Call_01e_4d91:
    ldh a, [$f3]
    and a
    ld a, $40
    ret z

    xor a
    ret


    push hl
    push de
    push bc
    push af
    call Call_000_3790
    call Call_01e_4e5e
    ld a, [$d059]
    and a
    jr z, jr_01e_4dcb

    cp $c1
    jr nz, jr_01e_4db4

    ld de, $4dcb
    push de
    jp Jump_01e_5e42


jr_01e_4db4:
    ld a, [$d2d4]
    bit 7, a
    jr nz, jr_01e_4dc3

    call Call_01e_4de1
    call Call_01e_4cb8
    jr jr_01e_4dc8

jr_01e_4dc3:
    ld c, $1e
    call Call_000_3781

jr_01e_4dc8:
    call Call_01e_4df8

jr_01e_4dcb:
    call Call_000_3790
    xor a
    ld [$d073], a
    ld [$d078], a
    ld [$d068], a
    dec a
    ld [$cf02], a
    pop af
    pop bc
    pop de
    pop hl
    ret


Call_01e_4de1:
    ldh a, [$f3]
    and a
    ret z

    ld a, [$d059]
    cp $85
    ld b, $bf
    jr z, jr_01e_4df3

    cp $9c
    ld b, $bd
    ret nz

jr_01e_4df3:
    ld a, b
    ld [$d059], a
    ret


Call_01e_4df8:
    ld a, [$cc5b]
    and a
    ret z

    dec a
    add a
    ld c, a
    ld b, $00
    ld hl, $4e0a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp hl


    ld d, $4e
    ld e, $4e
    ld h, $4e
    dec hl
    ld c, [hl]
    ld sp, $394e
    ld c, [hl]
    call Call_01e_5e96
    ld b, $08
    jp Jump_01e_5240


    call Call_01e_5e96
    ld b, $08
    jp Jump_01e_5247


    ld bc, $0602
    jr jr_01e_4e3c

    call Call_01e_5e96
    jp Jump_01e_53a0


    call Call_01e_5e96
    ld b, $02
    jp Jump_01e_5247


    ld bc, $0302

jr_01e_4e3c:
    push bc
    push bc

jr_01e_4e3e:
    ldh a, [rWX]
    inc a
    ldh [rWX], a
    ld c, $02
    call Call_000_3781
    dec b
    jr nz, jr_01e_4e3e

    pop bc

jr_01e_4e4c:
    ldh a, [rWX]
    dec a
    ldh [rWX], a
    ld c, $02
    call Call_000_3781
    dec b
    jr nz, jr_01e_4e4c

    pop bc
    dec c
    jr nz, jr_01e_4e3c

    ret


Call_01e_4e5e:
    ld a, [$cf15]
    and a
    ld a, $e4
    jr z, jr_01e_4e82

    ld a, $f0
    ld [$cc79], a
    ld b, $e4
    ld a, [$d059]
    cp $aa
    jr c, jr_01e_4e7a

    cp $ae
    jr nc, jr_01e_4e7a

    ld b, $f0

jr_01e_4e7a:
    ld a, b
    ldh [rOBP0], a
    ld a, $6c
    ldh [rOBP1], a
    ret


jr_01e_4e82:
    ld a, $e4
    ld [$cc79], a
    ldh [rOBP0], a
    ld a, $6c
    ldh [rOBP1], a
    ret


Call_01e_4e8e:
    ld a, [$cf02]
    cp $ff
    jr z, jr_01e_4e9b

    call Call_01e_58a6
    call Call_000_0e45

jr_01e_4e9b:
    ld hl, $c300
    ld a, l
    ld [$d07a], a
    ld a, h
    ld [$d079], a
    ld a, [$d074]
    ld h, a
    ld a, [$d073]
    ld l, a

Jump_01e_4eae:
    push hl
    ld c, [hl]
    ld b, $00
    ld hl, $6fa0
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld c, a
    ld a, [hl+]
    ld b, a
    pop hl
    inc hl
    push hl
    ld e, [hl]
    ld d, $00
    ld hl, $7cb1
    add hl, de
    add hl, de
    ld a, [hl+]
    ld [$d05f], a
    ld a, [hl]
    ld [$d05e], a
    pop hl
    inc hl
    ld a, [hl]
    ld [$d07b], a
    call Call_01e_4bc7
    call Call_01e_4f12
    ld a, [$d064]
    dec a
    ld [$d064], a
    ret z

    ld a, [$d074]
    ld h, a
    ld a, [$d073]
    ld l, a
    ld a, [$d068]
    cp $04
    ld bc, $0003
    jr nz, jr_01e_4ef7

    ld bc, $fffd

jr_01e_4ef7:
    add hl, bc
    ld a, h
    ld [$d074], a
    ld a, l
    ld [$d073], a
    jp Jump_01e_4eae


Call_01e_4f03:
Jump_01e_4f03:
    push hl
    push de
    push bc
    push af
    call Call_000_0b31
    call Call_000_0188
    pop af
    pop bc
    pop de
    pop hl
    ret


Call_01e_4f12:
    push hl
    push de
    push bc
    ld a, [$d059]
    ld hl, $4f30
    ld de, $0003
    call Call_000_3ddb
    jr nc, jr_01e_4f2c

    inc hl
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $4f2c
    push de
    jp hl


jr_01e_4f2c:
    pop bc
    pop de
    pop hl
    ret


    dec b
    push af
    ld d, c
    inc c
    push af
    ld d, c
    add hl, de
    push af
    ld d, c
    dec e
    push af
    ld d, c
    daa
    inc bc
    ld d, c
    dec l
    rst $28
    ld d, b
    ld [hl-], a
    push af
    ld d, c
    dec sp
    ld c, c
    ld d, b
    dec a
    push af
    ld d, c
    ccf
    push af
    ld d, c
    ld d, l
    ld [hl-], a
    ld d, b
    ld [hl], e
    push af
    ld d, c
    ld a, b
    dec sp
    ld d, b
    sub e
    push af
    ld d, c
    sbc c
    dec sp
    ld d, b
    sbc l
    inc d
    ld d, b
    xor d
    ld [hl], h
    ld d, b
    xor e
    ld a, a
    ld d, b
    xor h
    xor a
    ld d, b
    pop bc
    ld a, c
    ld c, a
    jp nz, Jump_01e_4fd1

    jp Jump_01e_5009


    push bc
    ld a, c
    ld c, a
    add $79
    ld c, a
    rst $38
    ld a, [$cf78]
    cp $03
    jr nc, jr_01e_4f86

    ldh a, [rOBP0]
    xor $3c
    ldh [rOBP0], a

jr_01e_4f86:
    ld a, [$d064]
    cp $0b
    jr nz, jr_01e_4f92

    ld a, $91
    call Call_000_0e45

jr_01e_4f92:
    ld a, [$d034]
    cp $02
    jr z, jr_01e_4fc6

    ld a, [$d0e3]
    cp $10
    ret nz

    ld a, [$d064]
    cp $03
    jr z, jr_01e_4fad

    cp $02
    jr z, jr_01e_4fad

    cp $01
    ret nz

jr_01e_4fad:
    ld hl, $c3b1
    ld de, $0014
    ld bc, $0707

jr_01e_4fb6:
    push hl
    push bc
    call Call_01e_5899
    pop bc
    pop hl
    add hl, de
    dec b
    jr nz, jr_01e_4fb6

    ld a, $08
    ldh [rNR10], a
    ret


jr_01e_4fc6:
    ld a, [$d064]
    cp $03
    ret nz

    dec a
    ld [$d064], a
    ret


Jump_01e_4fd1:
    ld a, [$d064]
    cp $04
    jr nz, jr_01e_4fe2

    ld a, $8c
    call Call_000_0e45
    ld c, $28
    call Call_000_3781

jr_01e_4fe2:
    ld a, [$d064]
    dec a
    ret nz

    ld a, [$cd3d]
    dec a
    ld [$cd3d], a
    ret z

    ld a, [$d073]
    ld l, a
    ld a, [$d074]
    ld h, a
    ld de, $fff4
    add hl, de
    ld a, l
    ld [$d073], a
    ld a, h
    ld [$d074], a
    ld a, $05
    ld [$d064], a
    ret


Jump_01e_5009:
    ld a, [$d064]
    cp $05
    ret nz

    ld a, $93
    jp Jump_000_0e45


    ld a, [$d064]
    cp $0c
    ret nc

    cp $08
    jr nc, jr_01e_5024

    cp $01
    jp z, Jump_01e_51f5

    ret


jr_01e_5024:
    ld b, $01
    ld a, $24
    call Call_000_3e9d
    ld b, $01
    ld a, $21
    jp Jump_000_3e9d


    ld a, [$d064]
    srl a
    call c, Call_01e_51f5
    ret


    ld a, [$d064]
    cp $01
    jp nz, Jump_01e_51f5

    ld hl, $c405
    jp Jump_01e_5838


    ld a, [$d064]
    cp $0d
    jp z, Jump_01e_51f5

    cp $09
    jp z, Jump_01e_51f5

    cp $05
    jp z, Jump_01e_51f5

    cp $01
    jp z, Jump_01e_51f5

    ret


    ld a, [$d064]
    cp $0e
    jp z, Jump_01e_51f5

    cp $09
    jp z, Jump_01e_51f5

    cp $02
    jp z, Jump_01e_51f5

    ret


    ld a, [$d064]
    cp $06
    ret nz

    ld a, $2f
    jp Jump_01e_5843


    ld a, [$d064]
    cp $01
    ret nz

    ld de, $50ab

jr_01e_5088:
    ld hl, $c300
    ld bc, $0004

jr_01e_508e:
    ld a, [de]
    cp $ff
    jr z, jr_01e_50a3

    add [hl]
    ld [hl], a
    add hl, bc
    ld a, l
    cp $10
    jr nz, jr_01e_508e

    inc de
    push bc
    call Call_000_3e07
    pop bc
    jr jr_01e_5088

jr_01e_50a3:
    call Call_01e_4f03
    ld a, $98
    jp Jump_000_0e45


    db $f4
    db $f4
    ld hl, sp-$01
    ld de, $50e6

jr_01e_50b2:
    ld hl, $c300
    ld bc, $0004

jr_01e_50b8:
    ld a, [de]
    cp $ff
    jp z, Jump_000_03bf

    add [hl]
    ld [hl], a
    add hl, bc
    ld a, l
    cp $10
    jr nz, jr_01e_50b8

    inc de
    push de
    ld a, [de]
    cp $0c
    jr z, jr_01e_50d1

    cp $ff
    jr nz, jr_01e_50d6

jr_01e_50d1:
    ld a, $ae
    call Call_000_0e45

jr_01e_50d6:
    push bc
    ld c, $05
    call Call_000_3781
    pop bc
    ldh a, [$ae]
    sub $08
    ldh [$ae], a
    pop de
    jr jr_01e_50b2

    dec bc
    inc c
    db $f4
    ld sp, hl
    rlca
    inc c
    ld hl, sp+$08
    rst $38
    ld hl, $c300
    ld de, $c310
    ld bc, $0010
    call Call_000_01bb
    ld a, [$d064]
    dec a
    call z, Call_01e_4f03
    ret


    ld a, $01
    ld [$d064], a
    ld c, $14
    jp Jump_000_3781


    cp $f5
    ld d, c
    db $fd
    dec c
    ld d, d
    db $fc
    ld hl, $fb52
    ld b, l
    ld d, d
    ld a, [$524c]
    ld sp, hl
    ld [de], a
    ld d, d
    ld hl, sp-$68
    ld d, c
    rst $30
    or c
    ld d, d
    or $ce
    ld d, d
    push af
    ret nz

    ld d, e
    db $f4
    and $52
    di
    and [hl]
    ld d, e
    ld a, [c]
    jr nc, jr_01e_5188

    pop af
    ld c, h
    ld d, h
    ldh a, [$2b]
    ld d, d
    rst $28
    jr c, jr_01e_5195

    xor $d8
    ld d, h
    db $ed
    jr nc, jr_01e_5198

    db $ec
    sbc l
    ld d, l
    db $eb
    or c
    ld d, a
    ld [$55d6], a
    jp hl


    nop
    ld d, [hl]
    add sp, -$42
    ld d, a
    rst $20
    xor e
    ld e, h
    and $ba
    ld e, h
    push hl
    ld a, h
    ld d, [hl]
    db $e4
    and a
    ld e, l
    db $e3
    and a
    ld e, l
    ld [c], a
    ld e, e
    ld d, h
    pop hl
    add e
    ld d, c
    ldh [$cf], a
    ld d, e
    rst $18
    rrca
    ld e, b
    sbc $a0
    ld d, e
    db $dd
    push de
    ld d, e
    call c, Call_01e_53e2
    db $db
    ldh a, [rHDMA2]
    jp c, Jump_01e_53e8

    reti


    rla
    ld d, a
    ret c

    sbc l
    ld d, [hl]
    rst $38
    ld c, $0a
    jp Jump_000_3781


Call_01e_5188:
Jump_01e_5188:
jr_01e_5188:
    ldh a, [$f3]
    push af
    xor $01
    ldh [$f3], a
    ld de, $5194
    push de
    jp hl


    pop af

jr_01e_5195:
    ldh [$f3], a
    ret


jr_01e_5198:
    ld a, $04
    ld [$d067], a
    ld a, [$cf15]
    and a
    ld hl, $51c1
    jr z, jr_01e_51a9

    ld hl, $51ce

jr_01e_51a9:
    push hl

jr_01e_51aa:
    ld a, [hl+]
    cp $01
    jr z, jr_01e_51b6

    ldh [rBGP], a
    call $51db
    jr jr_01e_51aa

jr_01e_51b6:
    ld a, [$d067]
    dec a
    ld [$d067], a
    pop hl
    jr nz, jr_01e_51a9

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
    ld bc, $fcf8
    rst $38
    db $fc
    ld hl, sp-$1c
    sub b
    ld b, b
    nop
    ld b, b
    sub b
    db $e4
    ld bc, $67fa
    ret nc

    cp $04
    ld c, $04
    jr z, jr_01e_51f2

    cp $03
    ld c, $03
    jr z, jr_01e_51f2

    cp $02
    ld c, $02
    jr z, jr_01e_51f2

    ld c, $01

jr_01e_51f2:
    jp Jump_000_3781


Call_01e_51f5:
Jump_01e_51f5:
    ldh a, [rBGP]
    push af
    ld a, $1b
    ldh [rBGP], a
    ld c, $02
    call Call_000_3781
    xor a
    ldh [rBGP], a
    ld c, $02
    call Call_000_3781
    pop af
    ldh [rBGP], a
    ret


    ld bc, $6f6f
    jr jr_01e_5233

    ld bc, $f9f4
    jr jr_01e_5233

    ld bc, $fef8
    jr jr_01e_5233

    ld bc, $ffff
    jr jr_01e_5233

    ld bc, $e4e4
    jr jr_01e_5233

    ld bc, $0000
    jr jr_01e_5233

    ld bc, $9090
    jr jr_01e_5233

    ld bc, $4040

jr_01e_5233:
    ld a, [$cf15]
    and a
    ld a, b
    jr z, jr_01e_523b

    ld a, c

jr_01e_523b:
    ldh [rBGP], a
    ret


    ld b, $05

Jump_01e_5240:
    ld a, $21
    jp Jump_000_3e9d


    ld b, $08

Jump_01e_5247:
    ld a, $24
    jp Jump_000_3e9d


    xor a
    ld [$d07c], a
    call Call_01e_403b
    ld d, $20
    ld a, $f0
    ld [$d05e], a
    ld a, $71
    ld [$d07c], a

jr_01e_525f:
    ld a, $10
    ld [$d05f], a
    ld a, $00
    ld [$d067], a
    call Call_01e_527d
    ld a, $18
    ld [$d05f], a
    ld a, $20
    ld [$d067], a
    call Call_01e_527d
    dec d
    jr nz, jr_01e_525f

    ret


Call_01e_527d:
    ld hl, $c300

jr_01e_5280:
    ld a, [$d05f]
    ld [hl+], a
    ld a, [$d05e]
    add $1b
    ld [$d05e], a
    ld [hl+], a
    ld a, [$d07c]
    ld [hl+], a
    xor a
    ld [hl+], a
    ld a, [$d05e]
    cp $90
    jr c, jr_01e_5280

    sub $a8
    ld [$d05e], a
    ld a, [$d05f]
    add $10
    ld [$d05f], a
    cp $70
    jr c, jr_01e_5280

    call Call_01e_4f03
    jp Jump_000_0b31


    ld c, $07
    ldh a, [$f3]
    and a
    ld hl, $c419
    ld de, $c405
    ld a, $30
    jr z, jr_01e_52c8

    ld hl, $c3c0
    ld de, $c3ac
    ld a, $ff

jr_01e_52c8:
    ld [$d07c], a
    jp Jump_01e_52f6


Call_01e_52ce:
    xor a
    call Call_01e_5879

jr_01e_52d2:
    call Call_01e_5857
    push bc
    push de
    call Call_01e_5ae5
    call Call_000_3e07
    call Call_01e_5838
    pop de
    pop bc
    dec b
    jr nz, jr_01e_52d2

    ret


Call_01e_52e6:
    ld e, $08
    ld a, $03
    ld [$d068], a
    jp Jump_01e_562f


    ld hl, $52e6
    jp Jump_01e_5188


Jump_01e_52f6:
jr_01e_52f6:
    push de
    push hl
    push bc
    ld b, $06

jr_01e_52fb:
    push bc
    push de
    push hl
    ld bc, $0007
    call Call_000_01bb
    pop de
    pop hl
    ld bc, $0028
    add hl, bc
    pop bc
    dec b
    jr nz, jr_01e_52fb

    ldh a, [$f3]
    and a
    ld hl, $c47d
    jr z, jr_01e_5319

    ld hl, $c424

jr_01e_5319:
    ld a, [$d07c]
    inc a
    ld [$d07c], a
    ld c, $07

jr_01e_5322:
    ld [hl+], a
    add $07
    dec c
    jr nz, jr_01e_5322

    ld c, $02
    call Call_000_3781
    pop bc
    pop hl
    pop de
    dec c
    jr nz, jr_01e_52f6

    ret


Call_01e_5334:
    ld a, $10
    ld [$d05e], a
    ld a, $30
    ld [$d05f], a
    ld hl, $c300
    ld d, $00
    ld c, $07

jr_01e_5345:
    ld a, [$d05f]
    ld e, a
    ld b, $05

jr_01e_534b:
    call Call_01e_5360
    inc d
    dec b
    jr nz, jr_01e_534b

    dec c
    ret z

    inc d
    inc d
    ld a, [$d05e]
    add $08
    ld [$d05e], a
    jr jr_01e_5345

Call_01e_5360:
    ld a, e
    add $08
    ld e, a
    ld [hl+], a
    ld a, [$d05e]
    ld [hl+], a
    ld a, d
    ld [hl+], a
    xor a
    ld [hl+], a
    ret


    ld l, e
    ld h, d

Call_01e_5370:
    ld de, $0004

jr_01e_5373:
    ld a, [$d067]
    ld b, a
    ld a, [hl]
    add b
    cp $a8
    jr c, jr_01e_5381

    dec hl
    ld a, $a0
    ld [hl+], a

jr_01e_5381:
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_01e_5373

    ret


    ld l, e
    ld h, d

Call_01e_5389:
    ld de, $0004

jr_01e_538c:
    ld a, [$d067]
    ld b, a
    ld a, [hl]
    add b
    cp $70
    jr c, jr_01e_539a

    dec hl
    ld a, $a0
    ld [hl+], a

jr_01e_539a:
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_01e_538c

    ret


Jump_01e_53a0:
    ld hl, $53a6
    jp Jump_01e_5188


    push af
    ld c, $06

jr_01e_53a9:
    push bc
    call Call_01e_5838
    ld c, $05
    call Call_000_3781
    call Call_01e_53d5
    ld c, $05
    call Call_000_3781
    pop bc
    dec c
    jr nz, jr_01e_53a9

    pop af
    ret


Call_01e_53c0:
    ld a, [$cffb]
    ld [$cee5], a
    ld a, [$cfcc]
    ld [$cee4], a
    jp Jump_01e_57ca


    ld hl, $53c0
    jp Jump_01e_5188


Call_01e_53d5:
Jump_01e_53d5:
    xor a
    call Call_01e_5879
    call Call_01e_5857
    call Call_01e_5ae5
    jp Jump_000_3e07


Call_01e_53e2:
    ld hl, $53d5
    jp Jump_01e_5188


Jump_01e_53e8:
    ldh a, [$f3]
    and a
    ld hl, $c404
    ld de, $c406
    jr z, jr_01e_53f9

    ld hl, $c3ab
    ld de, $c3ad

jr_01e_53f9:
    xor a
    ld c, $10

jr_01e_53fc:
    push af
    push bc
    push de
    push hl
    push hl
    push de
    push af
    push hl
    push hl
    call Call_01e_5879
    pop hl
    call Call_01e_5ae5
    call Call_000_3e07
    pop hl
    ld bc, $0709
    call Call_000_0374
    pop af
    call Call_01e_5879
    pop hl
    call Call_01e_5ae5
    call Call_000_3e07
    pop hl
    ld bc, $0709
    call Call_000_0374
    pop hl
    pop de
    pop bc
    pop af
    dec c
    jr nz, jr_01e_53fc

    ret


    call Call_01e_5838
    ldh a, [$f3]
    and a
    ld hl, $c406
    jr z, jr_01e_543e

    ld hl, $c3ab

jr_01e_543e:
    xor a
    push hl
    call Call_01e_5879
    pop hl
    call Call_01e_5ae5
    ld c, $03
    jp Jump_000_3781


    ldh a, [$f3]
    and a
    ld a, $66
    jr z, jr_01e_5455

    ld a, $0b

jr_01e_5455:
    call Call_01e_5843
    jp Jump_01e_53d5


    ldh a, [$f3]
    and a
    jr z, jr_01e_546c

    ld a, $d8
    ld [$d067], a
    ld a, $50
    ld [$d068], a
    jr jr_01e_5473

jr_01e_546c:
    xor a
    ld [$d067], a
    ld [$d068], a

jr_01e_5473:
    ld d, $7a
    ld c, $03
    xor a
    call Call_01e_581f
    ld hl, $54ad

jr_01e_547e:
    push hl
    ld c, $03
    ld de, $c300

jr_01e_5484:
    ld a, [hl]
    cp $ff
    jr z, jr_01e_54a6

    ld a, [$d067]
    add [hl]
    ld [de], a
    inc de
    inc hl
    ld a, [$d068]
    add [hl]
    ld [de], a
    inc hl
    inc de
    inc de
    inc de
    dec c
    jr nz, jr_01e_5484

    ld c, $05
    call Call_000_3781
    pop hl
    inc hl
    inc hl
    jr jr_01e_547e

jr_01e_54a6:
    pop hl
    call Call_01e_4f03
    jp Jump_01e_51f5


    jr c, @+$2a

    ld b, b
    jr @+$52

    db $10
    ld h, b
    jr jr_01e_551e

    jr z, jr_01e_5518

    jr c, @+$52

    ld b, b
    ld b, b
    jr c, @+$42

    jr z, jr_01e_5506

    ld e, $50
    jr @+$5d

    ld e, $60
    jr z, @+$5d

    ld [hl-], a
    ld d, b
    jr c, @+$48

    ld [hl-], a
    ld c, b
    jr z, @+$52

    jr nz, jr_01e_552a

    jr z, jr_01e_5524

    jr nc, @+$52

    jr z, @+$01

    ld c, $04

jr_01e_54da:
    push bc
    ldh a, [$f3]
    and a
    jr z, jr_01e_54e8

    ld hl, $c3b0
    ld de, $c3ae
    jr jr_01e_54ee

jr_01e_54e8:
    ld hl, $c409
    ld de, $c407

jr_01e_54ee:
    push de
    xor a
    ld [$d07c], a
    call Call_01e_550b
    pop hl
    ld a, $01
    ld [$d07c], a
    call Call_01e_550b
    pop bc
    dec c
    jr nz, jr_01e_54da

    call Call_01e_5838

jr_01e_5506:
    ld c, $02
    jp Jump_000_0b31


Call_01e_550b:
    ld c, $07

jr_01e_550d:
    push bc
    push hl
    ld c, $03
    ld a, [$d07c]
    cp $00
    jr nz, jr_01e_551e

jr_01e_5518:
    call Call_01e_5892
    dec hl
    jr jr_01e_5522

jr_01e_551e:
    call Call_01e_5899
    inc hl

jr_01e_5522:
    ld [hl], $7f

jr_01e_5524:
    pop hl
    ld de, $0014
    add hl, de
    pop bc

jr_01e_552a:
    dec c
    jr nz, jr_01e_550d

    jp Jump_000_3e07


    ldh a, [$f3]
    and a
    jr z, jr_01e_553a

    ld bc, $0080
    jr jr_01e_553d

jr_01e_553a:
    ld bc, $3028

jr_01e_553d:
    ld a, b
    ld [$d05f], a
    ld a, c
    ld [$d05e], a
    ld bc, $0501
    call Call_01e_554e
    jp Jump_01e_4f03


Call_01e_554e:
    push bc
    xor a
    ld [$d07c], a
    call Call_01e_403b
    pop bc
    ld d, $7a
    ld hl, $c300
    push bc
    ld a, [$d05f]
    ld e, a

jr_01e_5561:
    call Call_01e_5360
    dec b
    jr nz, jr_01e_5561

    call Call_000_0b31
    pop bc
    ld a, b
    ld [$d067], a

jr_01e_556f:
    push bc
    ld hl, $c300

jr_01e_5573:
    ld a, [$d05f]
    add $08
    ld e, a
    ld a, [hl]
    cp e
    jr z, jr_01e_5582

    add $fc
    ld [hl], a
    jr jr_01e_558b

jr_01e_5582:
    ld [hl], $00
    ld a, [$d067]
    dec a
    ld [$d067], a

jr_01e_558b:
    ld de, $0004
    add hl, de
    dec b
    jr nz, jr_01e_5573

    call Call_000_3781
    pop bc
    ld a, [$d067]
    and a
    jr nz, jr_01e_556f

    ret


    ldh a, [$f3]
    and a
    ld hl, $55c8
    ld a, $50
    jr z, jr_01e_55ac

    ld hl, $55cf
    ld a, $28

jr_01e_55ac:
    ld [$cd3d], a

jr_01e_55af:
    ld a, [$cd3d]
    ld [$d05f], a
    ld a, [hl+]
    cp $ff
    jp z, Jump_01e_4f03

    ld [$d05e], a
    ld bc, $0401
    push hl
    call Call_01e_554e
    pop hl
    jr jr_01e_55af

    db $10
    ld b, b
    jr z, @+$1a

    jr c, jr_01e_55fe

    rst $38
    ld h, b
    sub b
    ld a, b
    ld l, b
    adc b
    add b
    rst $38

Jump_01e_55d6:
    ld hl, $c6e8
    push hl
    xor a
    ld bc, $0310
    call Call_000_372a
    pop hl
    ld de, $0194
    add hl, de
    ld de, $55fb
    ld c, $05

jr_01e_55eb:
    ld a, [de]
    ld [hl+], a
    ld [hl+], a
    inc de
    dec c
    jr nz, jr_01e_55eb

    call Call_01e_5689
    call Call_000_3e07
    jp Jump_01e_53d5


    jr jr_01e_5639

    ld a, [hl]

jr_01e_55fe:
    inc a
    inc h
    ld a, $01
    ld c, $02

jr_01e_5604:
    push bc
    push af
    call Call_01e_5838
    pop af
    push af
    call Call_01e_5879
    call Call_01e_5857
    call Call_01e_5ae5
    ld c, $08
    call Call_000_3781
    pop af
    inc a
    pop bc
    dec c
    jr nz, jr_01e_5604

    call Call_01e_5838
    ld hl, $c6e8
    ld bc, $0310
    xor a
    call Call_000_372a
    jp Jump_01e_5689


Call_01e_562f:
Jump_01e_562f:
    ldh a, [$f3]
    and a
    jr z, jr_01e_5639

    ld hl, $c3ac
    jr jr_01e_563c

jr_01e_5639:
    ld hl, $c404

jr_01e_563c:
    ld d, $08

jr_01e_563e:
    push hl
    ld b, $07

jr_01e_5641:
    ld c, $08

jr_01e_5643:
    ldh a, [$f3]
    and a
    jr z, jr_01e_564d

    call Call_01e_5673
    jr jr_01e_5650

jr_01e_564d:
    call Call_01e_566a

jr_01e_5650:
    ld [hl+], a
    dec c
    jr nz, jr_01e_5643

    push de
    ld de, $000c
    add hl, de
    pop de
    dec b
    jr nz, jr_01e_5641

    ld a, [$d068]
    ld c, a
    call Call_000_3781
    pop hl
    dec d
    dec e
    jr nz, jr_01e_563e

    ret


Call_01e_566a:
    ld a, [hl]
    add $07
    cp $61
    ret c

    ld a, $7f
    ret


Call_01e_5673:
    ld a, [hl]
    sub $07
    cp $30
    ret c

    ld a, $7f
    ret


    ld e, $04
    ld a, $04
    ld [$d068], a
    call Call_01e_562f
    jp Jump_000_3e07


Call_01e_5689:
Jump_01e_5689:
    ldh a, [$f3]
    and a
    ld hl, $9310
    jr z, jr_01e_5694

    ld hl, $9000

jr_01e_5694:
    ld de, $c6e8
    ld bc, $0031
    jp Jump_000_02dd


    ld hl, $9800
    call Call_01e_5e37
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ld a, $90
    ldh [$b0], a
    ld d, $80
    ld e, $8f
    ld c, $ff
    ld hl, $56f6

jr_01e_56b6:
    push hl

jr_01e_56b7:
    call Call_01e_56e5
    ldh a, [rLY]
    cp e
    jr nz, jr_01e_56b7

    pop hl
    inc hl
    ld a, [hl]
    cp d
    jr nz, jr_01e_56c8

    ld hl, $56f6

jr_01e_56c8:
    dec c
    jr nz, jr_01e_56b6

    xor a
    ldh [$b0], a
    call Call_000_373e
    call Call_000_03bf
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    call Call_000_374a
    ld hl, $9c00
    call Call_01e_5e37
    ret


Call_01e_56e5:
jr_01e_56e5:
    ldh a, [rSTAT]
    and $03
    jr nz, jr_01e_56e5

    ld a, [hl]
    ldh [rSCX], a
    inc hl
    ld a, [hl]
    cp d
    ret nz

    ld hl, $56f6
    ret


    nop
    nop
    nop
    nop
    nop
    ld bc, $0101
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld bc, $0101
    nop
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    cp $fe
    cp $fe
    cp $ff
    rst $38
    rst $38
    add b

Call_01e_5717:
    ld hl, $c6e8
    xor a
    ld bc, $0310
    call Call_000_372a
    ldh a, [$f3]
    and a
    jr z, jr_01e_574c

    ld hl, $4780
    ld de, $c808
    call Call_01e_5776
    ld hl, $4790
    ld de, $c878
    call Call_01e_5776
    ld hl, $47a0
    ld de, $c818
    call Call_01e_5776
    ld hl, $47b0
    ld de, $c888
    call Call_01e_5776
    jr jr_01e_5770

jr_01e_574c:
    ld hl, $47c0
    ld de, $c878
    call Call_01e_5776
    ld hl, $47d0
    ld de, $c8e8
    call Call_01e_5776
    ld hl, $47e0
    ld de, $c888
    call Call_01e_5776
    ld hl, $47f0
    ld de, $c8f8
    call Call_01e_5776

jr_01e_5770:
    call Call_01e_5689
    jp Jump_01e_53d5


Call_01e_5776:
    ld bc, $0010
    ld a, $05
    jp Jump_000_028c


    ldh a, [$f3]
    and a
    ld hl, $ccf7
    ld a, [$d040]
    jr z, jr_01e_578f

    ld hl, $ccf3
    ld a, [$d045]

jr_01e_578f:
    push hl
    bit 4, a
    jr nz, jr_01e_5799

    call Call_01e_52ce
    jr jr_01e_579c

jr_01e_5799:
    call Call_01e_52e6

jr_01e_579c:
    pop hl
    ld a, [hl]
    and a
    jp nz, Jump_01e_55d6

    call Call_01e_53c0
    jp Jump_01e_53d5


    call Call_01e_52e6
    call Call_01e_5717
    jp Jump_01e_53d5


    ld c, $05

jr_01e_57b3:
    push bc
    call Call_01e_52ce
    pop bc
    dec c
    jr nz, jr_01e_57b3

    jp Jump_01e_53d5


    ld a, [$cfcc]
    ld [$cee5], a
    ld a, [$cffb]
    ld [$cee4], a

Jump_01e_57ca:
    ldh a, [$f3]
    and a
    jr z, jr_01e_57e7

    ld a, [$cee4]
    ld [$cf78], a
    ld [$d092], a
    xor a
    ld [$d087], a
    call Call_000_2f2e
    ld hl, $c3ac
    call Call_000_2d7f
    jr jr_01e_580a

jr_01e_57e7:
    ld a, [$cfc0]
    push af
    ld a, [$cee5]
    ld [$cfc0], a
    ld [$d092], a
    call Call_000_2f2e
    ld a, $04
    call Call_000_3e9d
    xor a
    call Call_01e_5879
    call Call_01e_5857
    call Call_01e_5ae5
    pop af
    ld [$cfc0], a

jr_01e_580a:
    ld b, $01
    jp Jump_000_3e1f


    xor a
    ldh [$ba], a
    ld hl, $5838
    call Call_01e_5188
    ld a, $01
    ldh [$ba], a
    jp Jump_000_3e07


Call_01e_581f:
    push bc
    push de
    ld [$d07c], a
    call Call_01e_403b
    pop de
    pop bc
    xor a
    ld e, a
    ld [$d05e], a
    ld hl, $c300

jr_01e_5831:
    call Call_01e_5360
    dec c
    jr nz, jr_01e_5831

    ret


Call_01e_5838:
Jump_01e_5838:
    ldh a, [$f3]
    and a
    jr z, jr_01e_5841

    ld a, $0c
    jr jr_01e_5843

jr_01e_5841:
    ld a, $65

Call_01e_5843:
Jump_01e_5843:
jr_01e_5843:
    push hl
    push de
    push bc
    ld e, a
    ld d, $00
    ld hl, $c3a0
    add hl, de
    ld bc, $0707
    call Call_000_0374
    pop bc
    pop de
    pop hl
    ret


Call_01e_5857:
    push de
    ldh a, [$f3]
    and a
    jr nz, jr_01e_5861

    ld a, $65
    jr jr_01e_5863

jr_01e_5861:
    ld a, $0c

jr_01e_5863:
    ld hl, $c3a0
    ld e, a
    ld d, $00
    add hl, de
    ld a, $07
    sub b
    and a
    jr z, jr_01e_5877

    ld de, $0014

jr_01e_5873:
    add hl, de
    dec a
    jr nz, jr_01e_5873

jr_01e_5877:
    pop de
    ret


Call_01e_5879:
    ld hl, $5b21
    ld e, a
    ld d, $00
    add hl, de
    add hl, de
    add hl, de
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld b, a
    and $0f
    ld c, a

jr_01e_588b:
    ld a, b
    swap a
    and $0f
    ld b, a
    ret


Call_01e_5892:
jr_01e_5892:
    ld a, [hl-]
    ld [hl+], a
    inc hl
    dec c
    jr nz, jr_01e_5892

    ret


Call_01e_5899:
jr_01e_5899:
    ld a, [hl+]
    ld [hl-], a
    dec hl
    dec c
    jr nz, jr_01e_5899

    ret


    ld a, b
    call Call_01e_58a6
    ld b, a
    ret


Call_01e_58a6:
    ld hl, $58f3
    ld e, a
    ld d, $00
    add hl, de
    add hl, de
    add hl, de
    ld a, [hl+]
    ld b, a
    call Call_01e_58e4
    jr nc, jr_01e_58da

    ldh a, [$f3]
    and a
    jr nz, jr_01e_58c0

    ld a, [$cffb]
    jr jr_01e_58c3

jr_01e_58c0:
    ld a, [$cfcc]

jr_01e_58c3:
    push hl
    call Call_000_2dd0
    ld b, a
    pop hl
    ld a, [$c0f1]
    add [hl]
    ld [$c0f1], a
    inc hl
    ld a, [$c0f2]
    add [hl]
    ld [$c0f2], a
    jr jr_01e_58e2

jr_01e_58da:
    ld a, [hl+]
    ld [$c0f1], a
    ld a, [hl+]
    ld [$c0f2], a

jr_01e_58e2:
    ld a, b
    ret


Call_01e_58e4:
    ld a, [$d059]
    cp $2d
    jr z, jr_01e_58f1

    cp $2e
    jr z, jr_01e_58f1

    and a
    ret


jr_01e_58f1:
    scf
    ret


    and b
    nop
    add b
    and d
    db $10
    add b
    or e
    nop
    add b
    and c
    ld bc, $a380
    nop
    ld b, b
    jp hl


    nop
    rst $38
    and e
    db $10
    ld h, b
    and e
    jr nz, jr_01e_588b

    and e
    nop
    and b
    and [hl]
    nop
    add b
    and l
    jr nz, jr_01e_5954

    and l
    nop
    add b
    and h
    nop
    and b
    and a
    db $10
    ret nz

    and a
    nop
    and b
    xor b
    nop
    ret nz

    xor b
    db $10

jr_01e_5925:
    and b
    xor c
    nop
    ldh [$a7], a
    jr nz, @-$3e

    xor d
    nop

jr_01e_592e:
    add b
    cp c
    nop
    add b
    xor e
    ld bc, $b780
    nop
    add b
    xor l
    ldh a, [rLCDC]
    or b
    nop
    add b
    xor l
    nop
    add b
    cp b
    db $10
    add b
    or c
    ld bc, $aea0
    nop
    add b
    or h
    nop
    ld h, b
    or h
    ld bc, $b640
    nop
    and b
    or b

jr_01e_5954:
    db $10
    and b
    or a
    nop
    ret nz

    xor d
    db $10
    ld h, b
    or b
    nop
    and b
    cp c
    ld de, $b0c0
    jr nz, jr_01e_5925

    cp b
    nop
    add b
    or c
    nop
    add b
    or c
    jr nz, jr_01e_592e

    xor a
    nop
    add b
    db $db

jr_01e_5972:
    rst $38
    ld b, b
    or h
    nop
    add b
    and c
    nop
    ret nz

    and c
    nop
    ld b, b
    db $e4
    nop
    add b
    cp a
    ld b, b
    ld h, b
    cp a
    nop
    add b
    cp a
    rst $38
    ld b, b
    rst $00
    add b
    ret nz

    xor a
    db $10
    and b
    xor a
    ld hl, $c5e0
    nop
    add b
    cp e
    jr nz, jr_01e_59f8

    rst $00
    nop
    add b
    call z, $8000
    jp nz, $8040

    push bc
    ldh a, [$e0]
    rst $08
    nop
    add b
    rst $00
    ldh a, [$60]
    jp nz, $8000

    and $00
    add b
    sbc l
    ld bc, $a9a0

jr_01e_59b4:
    ldh a, [rNR41]
    cp d
    ld bc, $bac0
    nop
    add b
    or b
    nop
    ldh [$be], a
    ld bc, $be60
    jr nz, jr_01e_5a05

jr_01e_59c5:
    cp e
    nop
    add b
    cp e
    ld b, b
    ret nz

    or c
    inc bc
    ld h, b
    cp l
    ld de, $a8e0
    jr nz, jr_01e_59b4

    jp nc, $8000

    or d
    nop
    add b
    or d
    ld de, $b2a0
    ld bc, $a9c0
    inc d
    ret nz

jr_01e_59e3:
    or c
    ld [bc], a
    and b
    push bc
    ldh a, [$80]
    push bc
    jr nz, @-$3e

    push de
    nop
    jr nz, jr_01e_59c5

    jr nz, jr_01e_5972

    jp nc, Jump_01e_6012

    cp [hl]
    nop
    add b

jr_01e_59f8:
    xor d
    ld bc, $c5e0
    rrca
    ldh [$c5], a
    ld de, $a620
    db $10
    ld b, b
    and l

jr_01e_5a05:
    db $10
    ret nz

    xor d
    nop
    jr nz, jr_01e_59e3

    nop
    add b
    db $e4
    ld de, $9f18
    jr nz, @-$3e

    sbc [hl]
    jr nz, @-$3e

    cp l
    nop
    db $10
    cp [hl]
    ldh a, [rNR41]
    rst $18
    ldh a, [$c0]
    and a
    ldh a, [$e0]
    sbc a
    ldh a, [rLCDC]
    db $db
    nop

jr_01e_5a27:
    add b
    rst $18
    add b
    ld b, b

jr_01e_5a2b:
    rst $18
    nop
    add b
    xor d
    ld de, $aa20
    ld [hl+], a
    db $10
    or c
    pop af
    rst $38
    xor c
    pop af
    rst $38

jr_01e_5a3a:
    xor d
    inc sp
    jr nc, @-$21

    ld b, b
    ret nz

    and h
    jr nz, jr_01e_5a63

    and h
    ldh a, [rNR10]
    and l
    ld hl, sp+$10
    and a
    ldh a, [rNR10]
    cp l
    nop
    add b
    xor [hl]
    nop
    ret nz

    db $dd
    ret nz

    rst $38
    sbc a
    ld a, [c]
    jr nz, jr_01e_5a3a

    nop
    add b
    pop hl
    nop
    ld b, b
    sbc a
    nop
    ld b, b
    and a
    db $10

jr_01e_5a63:
    rst $38
    rst $00
    jr nz, @+$22

    db $dd
    nop
    add b
    push bc
    rra
    jr nz, jr_01e_5a2b

    cpl
    add b
    and l
    rra
    rst $38
    jp z, Jump_01e_601f

    cp [hl]
    ld e, $20
    cp [hl]
    rra
    jr jr_01e_5a27

    rrca
    add b

jr_01e_5a7f:
    sbc a
    ld hl, sp+$10
    sbc [hl]
    jr jr_01e_5aa5

    db $dd
    ld [$ad40], sp
    ld bc, $a7e0
    add hl, bc
    rst $38
    db $e4
    ld b, d
    ld bc, $00b2
    rst $38
    db $dd
    ld [$bbe0], sp
    nop
    add b
    sbc a
    adc b
    db $10
    cp l
    ld c, b
    rst $38
    sbc [hl]
    rst $38
    rst $38
    cp e
    rst $38

jr_01e_5aa5:
    db $10
    sbc [hl]
    rst $38
    inc b
    or d
    ld bc, $a9ff
    ld hl, sp-$01
    and d
    ldh a, [$f0]
    and l
    ld [$a310], sp
    ldh a, [rIE]
    or b
    ldh a, [rIE]
    pop hl
    db $10
    rst $38
    and h
    ldh a, [rNR41]
    jp z, Jump_01e_60f0

    cp b
    ld [de], a
    db $10
    and $f0
    jr nz, jr_01e_5a7f

    ld [de], a
    rst $38
    db $db
    add b
    inc b
    rst $18
    ldh a, [rNR10]
    push bc
    ld hl, sp-$01
    cp [hl]
    ldh a, [rIE]
    and a
    ld bc, $ccff
    ret c

    inc b
    and c
    nop
    add b
    and c
    nop
    add b

Call_01e_5ae5:
    ldh a, [$f3]
    and a
    ld a, $31
    jr z, jr_01e_5aed

    xor a

jr_01e_5aed:
    ldh [$8b], a
    jr jr_01e_5b02

    call Call_000_3ec4
    ld a, [$cd67]
    and a
    jr nz, jr_01e_5aff

    ld de, $5b39
    jr jr_01e_5b02

jr_01e_5aff:
    ld de, $5b52

jr_01e_5b02:
    xor a
    ldh [$ba], a

Jump_01e_5b05:
    push hl

jr_01e_5b06:
    push bc
    push hl
    ldh a, [$8b]
    ld b, a

jr_01e_5b0b:
    ld a, [de]
    add b
    inc de
    ld [hl+], a
    dec c
    jr nz, jr_01e_5b0b

    pop hl
    ld bc, $0014
    add hl, bc
    pop bc
    dec b
    jr nz, jr_01e_5b06

    ld a, $01
    ldh [$ba], a
    pop hl
    ret


    ld e, e
    ld e, e
    ld [hl], a
    adc h
    ld e, e
    ld d, a
    xor a
    ld e, e
    scf
    call nz, Call_01e_775b
    push af
    ld e, e
    ld [hl], a
    ld h, $5c
    ld [hl], a
    ld d, a
    ld e, h
    add [hl]
    add a
    ld e, h
    inc a
    ld sp, $4638
    ld d, h
    ld e, e
    ld [hl-], a
    add hl, sp
    ld b, a
    ld d, l
    ld e, h
    inc [hl]
    dec sp
    ld c, c
    ld d, a
    ld e, [hl]
    ld [hl], $3d
    ld c, e
    ld e, c
    ld h, b
    scf
    ld a, $4c
    ld e, d
    ld h, c
    ld sp, $5b46
    inc [hl]
    ld c, c
    ld e, [hl]
    scf
    ld c, h
    ld h, c
    nop
    rlca
    ld c, $15
    inc e
    inc hl
    ld a, [hl+]
    ld bc, $0f08
    ld d, $1d
    inc h
    dec hl
    ld [bc], a
    add hl, bc
    db $10
    rla
    ld e, $25
    inc l
    inc bc
    ld a, [bc]
    ld de, $1f18
    ld h, $2d
    inc b
    dec bc
    ld [de], a
    add hl, de
    jr nz, jr_01e_5ba4

    ld l, $05
    inc c
    inc de
    ld a, [de]
    ld hl, $2f28
    ld b, $0d
    inc d
    dec de
    ld [hl+], a
    add hl, hl
    jr nc, jr_01e_5b8d

jr_01e_5b8d:
    rlca
    ld c, $15
    inc e
    inc hl
    ld a, [hl+]
    ld bc, $0f08
    ld d, $1d
    inc h
    dec hl
    inc bc
    ld a, [bc]
    ld de, $1f18
    ld h, $2d
    inc b
    dec bc
    ld [de], a

jr_01e_5ba4:
    add hl, de
    jr nz, jr_01e_5bce

    ld l, $05
    inc c
    inc de
    ld a, [de]
    ld hl, $2f28
    nop
    rlca
    ld c, $15
    inc e
    inc hl
    ld a, [hl+]
    ld [bc], a
    add hl, bc
    db $10
    rla
    ld e, $25
    inc l
    inc b
    dec bc
    ld [de], a
    add hl, de
    jr nz, @+$29

    ld l, $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01e_5bce:
    nop
    nop
    add hl, de
    nop
    ld [bc], a
    ld b, $0b
    db $10
    inc d
    ld a, [de]
    nop
    nop
    rlca
    inc c
    ld de, $1b15
    nop
    inc bc
    ld [$120d], sp
    ld d, $1c
    nop
    inc b
    add hl, bc
    ld c, $13
    rla
    dec e
    rra
    dec b
    ld a, [bc]
    rrca
    ld bc, $1e18
    jr nz, jr_01e_5bf6

jr_01e_5bf6:
    nop
    nop
    jr nc, jr_01e_5bfa

jr_01e_5bfa:
    scf
    nop
    nop
    nop
    dec hl
    ld sp, $3834
    dec a
    ld hl, $2c26
    ld bc, $3935
    ld a, $22
    daa
    dec l
    ld [hl-], a
    ld [hl], $01
    nop
    inc hl
    jr z, jr_01e_5c42

    inc sp
    ld bc, $003a
    inc h
    add hl, hl
    cpl
    ld bc, $3b01
    nop
    dec h
    ld a, [hl+]
    ld bc, $0101
    inc a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, a
    ld c, l
    nop
    nop
    nop
    nop
    nop
    ld c, b
    ld c, [hl]
    ld d, d
    ld d, [hl]
    ld e, e
    ccf
    ld b, e
    ld c, c
    ld c, a
    ld d, e
    ld d, a
    ld e, h

jr_01e_5c42:
    ld b, b
    ld b, h
    ld c, d
    ld d, b
    ld d, h
    ld e, b
    nop
    ld b, c
    ld b, l
    ld c, e
    ld d, c
    ld c, h
    ld e, c
    ld e, l
    ld b, d
    ld b, [hl]
    ld c, h
    ld c, h
    ld d, l
    ld e, d
    ld e, [hl]
    ld sp, $3232
    ld [hl-], a
    ld [hl-], a
    inc sp
    inc [hl]
    dec [hl]
    ld [hl], $36
    scf
    jr c, jr_01e_5c98

    add hl, sp
    ld a, [hl-]
    ld a, [hl-]
    dec sp
    jr c, jr_01e_5ca6

    dec a
    ld a, $3e
    ccf
    ld b, b
    ld b, c
    ld b, d
    ld b, e
    ld b, e
    ld b, h
    ld b, l
    ld b, [hl]
    ld b, a
    ld b, e
    ld c, b
    ld c, c
    ld c, d
    ld b, c
    ld b, e
    ld c, e
    ld c, h
    ld c, l
    ld c, [hl]
    ld c, a
    ld d, b
    ld d, b
    ld d, b
    ld d, c
    ld d, d
    ld b, e
    ld d, l
    ld d, [hl]
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld b, e
    ld d, a
    ld e, b
    ld d, h
    ld d, h

jr_01e_5c98:
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    ld e, c
    ld e, d
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_01e_5ca6:
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld a, [$cc79]
    ldh [rOBP0], a
    ld d, $37
    ld a, $03
    ld [$d068], a
    jp Jump_01e_5cc7


    ld d, $71
    ld a, $14
    ld [$d068], a
    call Call_01e_5cc7
    jp Jump_000_0188


Call_01e_5cc7:
Jump_01e_5cc7:
    ld c, a
    ld a, $01
    call Call_01e_581f
    call Call_01e_5d5a
    call Call_01e_5d82
    ld hl, $c300
    ld [hl], $00

jr_01e_5cd8:
    ld hl, $cd3d
    ld de, $0000
    ld a, [$d068]
    ld c, a

jr_01e_5ce2:
    push bc
    push hl
    push de
    ld a, [hl]
    ld [$d067], a
    call Call_01e_5d46
    call Call_01e_5d0b
    pop de
    ld hl, $0004
    add hl, de
    ld e, l
    ld d, h
    pop hl
    ld a, [$d067]
    ld [hl+], a
    pop bc
    dec c
    jr nz, jr_01e_5ce2

    call Call_000_3e07
    ld hl, $c300
    ld a, [hl]
    cp $68
    jr nz, jr_01e_5cd8

    ret


Call_01e_5d0b:
    ld hl, $c300
    add hl, de
    ld a, [hl]
    inc a
    inc a
    cp $70
    jr c, jr_01e_5d18

    ld a, $a0

jr_01e_5d18:
    ld [hl+], a
    ld a, [$d067]
    ld b, a
    ld de, $5d3d
    and $7f
    add e
    jr nc, jr_01e_5d26

    inc d

jr_01e_5d26:
    ld e, a
    ld a, b
    and $80
    jr nz, jr_01e_5d33

    ld a, [de]
    add [hl]
    ld [hl+], a
    inc hl
    xor a
    jr jr_01e_5d3b

jr_01e_5d33:
    ld a, [de]
    ld b, a
    ld a, [hl]
    sub b
    ld [hl+], a
    inc hl
    ld a, $20

jr_01e_5d3b:
    ld [hl], a
    ret


    nop
    ld bc, $0503
    rlca
    add hl, bc
    dec bc
    dec c
    rrca

Call_01e_5d46:
    ld a, [$d067]
    inc a
    ld b, a
    and $7f
    cp $09
    ld a, b
    jr nz, jr_01e_5d56

    and $80
    xor $80

jr_01e_5d56:
    ld [$d067], a
    ret


Call_01e_5d5a:
    ld hl, $c301
    ld de, $5d6e
    ld a, [$d068]
    ld c, a

jr_01e_5d64:
    ld a, [de]
    ld [hl+], a
    inc hl
    inc hl
    inc hl
    inc de
    dec c
    jr nz, jr_01e_5d64

    ret


    jr c, jr_01e_5db0

    ld d, b
    ld h, b
    ld [hl], b
    adc b
    sub b
    ld d, [hl]
    ld h, a
    ld c, d
    ld [hl], a
    add h
    sbc b
    ld [hl-], a
    ld [hl+], a
    ld e, h
    ld l, h
    ld a, l
    adc [hl]
    sbc c

Call_01e_5d82:
    ld hl, $cd3d
    ld de, $5d93
    ld a, [$d068]
    ld c, a

jr_01e_5d8c:
    ld a, [de]
    ld [hl+], a
    inc de
    dec c
    jr nz, jr_01e_5d8c

    ret


    nop
    add h
    ld b, $81
    ld [bc], a
    adc b
    ld bc, $0583
    adc c
    add hl, bc
    add b
    rlca
    add a
    inc bc
    add d
    inc b
    add l
    ld [$1186], sp
    db $10
    sub e
    ld hl, $8000
    ld bc, $0031

jr_01e_5db0:
    call Call_000_02dd
    xor a
    ldh [$ae], a
    ld hl, $9800
    call Call_01e_5e37
    ld a, $90
    ldh [$b0], a
    ld hl, $9b20
    call Call_01e_5e37
    ld a, $38
    ldh [$b0], a
    call Call_01e_5334
    ld hl, $9800
    call Call_01e_5e37
    call Call_01e_5838
    call Call_000_3e07
    ld de, $0208
    call Call_01e_5e13
    call Call_01e_53d5
    call Call_000_0188
    ld a, $90
    ldh [$b0], a
    ld hl, $9c00
    call Call_01e_5e37
    xor a
    ldh [$b0], a
    call Call_000_3761
    ld hl, $9800
    call Call_01e_5e37
    call Call_000_376d
    ld hl, $9c00
    jp Jump_01e_5e37


    call Call_000_3ec4
    ld a, c
    ldh [$8b], a
    ld a, b
    push hl
    call Call_01e_5879
    pop hl
    jp Jump_01e_5b05


Call_01e_5e13:
    ldh a, [$ae]
    ld [$cd3d], a

jr_01e_5e18:
    ld a, [$cd3d]
    add d
    ldh [$ae], a
    ld c, $02
    call Call_000_3781
    ld a, [$cd3d]
    sub d
    ldh [$ae], a
    ld c, $02
    call Call_000_3781
    dec e
    jr nz, jr_01e_5e18

    ld a, [$cd3d]
    ldh [$ae], a
    ret


Call_01e_5e37:
Jump_01e_5e37:
    ld a, h
    ld [$ffbd], a
    ld a, l
    ld [$ffbc], a
    jp Jump_000_3e07


Jump_01e_5e42:
    ld a, [$d034]
    cp $02
    jr z, @+$3a

    ld a, [$d0e3]
    ld b, a
    and $f0
    swap a
    ld c, a
    ld a, b
    and $0f
    ld [$cd3d], a
    ld hl, $5e7c
    ld a, [$cf78]
    cp $04
    ld b, $c1
    jr z, jr_01e_5e6c

    cp $03
    ld b, $c5
    jr z, jr_01e_5e6c

    ld b, $c6

jr_01e_5e6c:
    ld a, b

jr_01e_5e6d:
    ld [$d059], a
    push bc
    push hl
    call Call_01e_4cb8
    pop hl
    ld a, [hl+]
    pop bc
    dec c
    jr nz, jr_01e_5e6d

    ret


    jp $c2c8


    jp Jump_000_3ea6


    pop bc
    ld [$d059], a
    call Call_01e_4cb8
    ld a, $95
    call Call_000_0e45
    ld a, $c4
    ld [$d059], a
    jp Jump_01e_4cb8


Call_01e_5e96:
    call Call_000_3790
    ld a, [$d038]
    and $7f
    ret z

    cp $0a
    ld a, $20
    ld b, $30
    ld c, $a6
    jr z, jr_01e_5eb7

    ld a, $e0
    ld b, $ff
    ld c, $b0
    jr nc, jr_01e_5eb7

    ld a, $50
    ld b, $01
    ld c, $a7

jr_01e_5eb7:
    ld [$c0f1], a
    ld a, b
    ld [$c0f2], a
    ld a, c
    jp Jump_000_0e45


    ld a, [$cd4d]
    cp $52
    jr z, jr_01e_5ef4

    ld c, $08

jr_01e_5ecb:
    push bc
    ld hl, $c391
    ld a, $01
    ld [$d067], a
    ld c, $02
    call Call_01e_5370
    ld hl, $c399
    ld a, $ff
    ld [$d067], a
    ld c, $02
    call Call_01e_5370
    ldh a, [rOBP1]
    xor $64
    ldh [rOBP1], a
    call Call_000_0b31
    pop bc
    dec c
    jr nz, jr_01e_5ecb

    ret


jr_01e_5ef4:
    ld c, $02

jr_01e_5ef6:
    push bc
    ld c, $08
    call Call_01e_5f19
    call Call_01e_5f5c
    ld c, $08
    call Call_01e_5f19
    call Call_01e_5f5c
    ld hl, $c390
    ld a, $02
    ld [$d067], a
    ld c, $04
    call Call_01e_5389
    pop bc
    dec c
    jr nz, jr_01e_5ef6

    ret


Call_01e_5f19:
jr_01e_5f19:
    push bc
    ld hl, $c391
    ld a, $01
    ld [$d067], a
    ld c, $01
    call Call_01e_5370
    ld hl, $c395
    ld a, $02
    ld [$d067], a
    ld c, $01
    call Call_01e_5370
    ld hl, $c399
    ld a, $fe
    ld [$d067], a
    ld c, $01
    call Call_01e_5370
    ld hl, $c39d
    ld a, $ff
    ld [$d067], a
    ld c, $01
    call Call_01e_5370
    ldh a, [rOBP1]
    xor $64
    ldh [rOBP1], a
    call Call_000_0b31
    pop bc
    dec c
    jr nz, jr_01e_5f19

    ret


Call_01e_5f5c:
    ld hl, $c390
    ld de, $cee4
    ld bc, $0008
    call Call_000_01bb
    ld hl, $c398
    ld de, $c390
    ld bc, $0008
    call Call_000_01bb
    ld hl, $cee4
    ld de, $c398
    ld bc, $0008
    jp Jump_000_01bb


    ld a, $01
    ld [$cd50], a
    ld a, [$cfb2]
    push af
    ld a, $ff
    ld [$cfb2], a
    ld a, $e4
    ldh [rOBP1], a
    call Call_01e_5fec
    ld b, $03
    ld hl, $7387
    call Call_000_3620
    ld c, $08

jr_01e_5f9f:
    push bc
    call Call_01e_5fbe
    ld bc, $5faa
    push bc
    ld c, $04
    jp hl


    ldh a, [rOBP1]
    xor $64
    ldh [rOBP1], a
    call Call_000_3e07
    pop bc
    dec c
    jr nz, jr_01e_5f9f

    pop af
    ld [$cfb2], a
    jp Jump_000_23ae


Call_01e_5fbe:
    ld a, [$c109]
    ld hl, $5fdc
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld [$d067], a
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    push hl
    ld hl, $c390
    ld d, $00
    add hl, de
    ld e, l
    ld d, h
    pop hl
    ret


    rst $38
    nop
    add a
    ld d, e
    ld bc, $8700
    ld d, e
    ld bc, $6e01
    ld d, e
    rst $38
    ld bc, $536e

Call_01e_5fec:
    ld hl, $8fc0
    ld c, $04

jr_01e_5ff1:
    push bc
    push hl
    call Call_01e_6000
    pop hl
    ld bc, $0010
    add hl, bc
    pop bc
    dec c
    jr nz, jr_01e_5ff1

    ret


Call_01e_6000:
    ld de, $6009
    ld bc, $1e01
    jp Jump_000_02dd


    nop
    jr jr_01e_6026

    ld h, [hl]
    inc b
    ld b, d
    dec bc
    add c
    ld d, [hl]

Jump_01e_6012:
    adc c
    ld a, [de]
    ld l, $4c
    ld [de], a
    jr c, jr_01e_6051

    ccf
    ld [hl-], a
    rra
    jr jr_01e_604d

    ccf

Jump_01e_601f:
    daa
    ccf
    rra
    add hl, de
    rra
    add hl, de
    rla

jr_01e_6026:
    rra
    rrca
    rrca
    db $fc
    ld c, h
    ld hl, sp+$18
    db $f4
    db $fc
    db $e4
    db $fc
    ld hl, sp-$68
    ld hl, sp-$68
    add sp, -$08
    ldh a, [$f0]
    ccf
    inc sp
    inc l
    ccf
    dec hl
    ccf
    add hl, de
    ld e, $1c
    rra
    rla
    rra
    ld de, $0e1f
    ld c, $fc
    call z, $fc34

jr_01e_604d:
    call nc, $98fc
    ld a, b

jr_01e_6051:
    jr c, @-$06

    add sp, -$08
    adc b
    ld hl, sp+$70
    ld [hl], b
    rst $18
    ret nc

    ei
    db $fc
    ccf
    ccf

jr_01e_605f:
    inc a
    daa
    ccf
    daa
    ld e, $1f
    inc b
    rlca
    inc bc
    inc bc
    ldh a, [rNR10]
    ldh [$60], a
    jr nc, jr_01e_605f

    ld [hl], b
    ldh a, [$d0]
    ldh a, [rSVBK]
    ldh a, [rNR41]
    ldh [$c0], a
    ret nz

    jr jr_01e_6093

    jr jr_01e_6095

    jr jr_01e_6097

    jr jr_01e_6099

    jr jr_01e_609b

    jr jr_01e_609d

    jr jr_01e_609f

    jr jr_01e_60a1

    ret nz

    ret nz

    ldh a, [$f0]
    inc a
    inc a
    rrca
    rrca
    inc bc
    inc bc

jr_01e_6093:
    nop
    nop

jr_01e_6095:
    nop
    nop

jr_01e_6097:
    nop
    nop

jr_01e_6099:
    ld [bc], a
    ld [bc], a

jr_01e_609b:
    rlca
    dec b

jr_01e_609d:
    rlca
    dec b

jr_01e_609f:
    adc l
    adc e

jr_01e_60a1:
    db $ed
    db $eb
    sbc $d6
    cp b
    cp b
    ld h, b
    ld h, b
    ld b, d
    ld h, d
    ld b, [hl]
    ld h, d
    ld c, d
    ld h, d
    ld d, c
    ld h, d
    ld e, b
    ld h, d
    ld e, h
    ld h, d
    ld h, e
    ld h, d
    ld l, d
    ld h, d
    ld [hl], c
    ld h, d
    ld a, h
    ld h, d
    add b
    ld h, d
    add h
    ld h, d
    adc b
    ld h, d
    adc h
    ld h, d
    sub [hl]
    ld h, d
    sbc h
    ld h, d
    and e
    ld h, d
    and a
    ld h, d
    xor l
    ld h, d
    or e
    ld h, d
    cp d
    ld h, d
    cp [hl]
    ld h, d
    push bc
    ld h, d
    ret


    ld h, d
    ret nc

    ld h, d
    call nc, $d862
    ld h, d
    sbc $62
    ld [c], a
    ld h, d
    and $62
    db $ed
    ld h, d
    db $f4
    ld h, d
    inc b
    ld h, e
    add hl, bc
    ld h, e
    ld [de], a
    ld h, e
    inc e

Jump_01e_60f0:
    ld h, e
    inc hl
    ld h, e
    daa
    ld h, e
    dec [hl]
    ld h, e
    ld b, h
    ld h, e
    ld c, b
    ld h, e
    ld c, a
    ld h, e
    ld d, e
    ld h, e
    ld e, h
    ld h, e
    ld h, b
    ld h, e
    ld h, h
    ld h, e
    ld l, [hl]
    ld h, e
    ld a, b
    ld h, e
    ld a, h
    ld h, e
    adc c
    ld h, e
    sub d
    ld h, e
    sbc c
    ld h, e
    sbc l
    ld h, e
    and a
    ld h, e
    xor [hl]
    ld h, e
    or d
    ld h, e
    cp c
    ld h, e
    cp a
    ld h, e
    add $63
    call $d363
    ld h, e
    rst $10
    ld h, e
    rst $18
    ld h, e
    ldh a, [$63]
    db $f4
    ld h, e
    ld hl, sp+$63
    nop
    ld h, h
    ld [$1064], sp
    ld h, h
    ld a, [hl+]
    ld h, h
    ld [hl-], a
    ld h, h
    dec a
    ld h, h
    ld c, h
    ld h, h
    ld d, e
    ld h, h
    ld e, d
    ld h, h
    ld h, e
    ld h, h
    ld l, d
    ld h, h
    ld l, [hl]
    ld h, h
    ld [hl], d
    ld h, h
    db $76
    ld h, h
    ld a, l
    ld h, h
    add c
    ld h, h
    adc [hl]
    ld h, h
    sbc b
    ld h, h
    sbc h
    ld h, h
    and e
    ld h, h
    xor l
    ld h, h
    cp h
    ld h, h
    ret nz

    ld h, h
    push bc
    ld h, h
    adc $64
    call nc, $da64
    ld h, h
    db $dd
    ld h, h
    ld [c], a
    ld h, h
    push hl
    ld h, h
    rst $28
    ld h, h
    db $f4
    ld h, h
    db $fc
    ld h, h
    nop
    ld h, l
    dec b
    ld h, l
    ld a, [bc]
    ld h, l
    ld de, $1565
    ld h, l
    add hl, hl
    ld h, l
    ld [hl-], a
    ld h, l
    inc a
    ld h, l
    ld b, l
    ld h, l
    ld h, [hl]
    ld h, l
    ld l, [hl]
    ld h, l
    ld a, d
    ld h, l
    add h
    ld h, l
    adc e
    ld h, l
    sub [hl]
    ld h, l
    sbc l
    ld h, l
    xor b
    ld h, l
    xor e
    ld h, l
    xor a
    ld h, l
    cp [hl]
    ld h, l
    jp nz, $c665

    ld h, l
    call $d165
    ld h, l
    reti


    ld h, l
    ldh [$65], a
    db $e4
    ld h, l
    db $f4
    ld h, l
    rst $38
    ld h, l
    add hl, bc
    ld h, [hl]
    dec c
    ld h, [hl]
    ld de, $1566
    ld h, [hl]
    rra
    ld h, [hl]
    ld h, $66
    ld a, [hl+]
    ld h, [hl]
    jr c, jr_01e_621f

    inc a
    ld h, [hl]
    ld b, l
    ld h, [hl]
    ld c, a
    ld h, [hl]
    ld d, e
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld l, b
    ld h, [hl]
    ld l, h
    ld h, [hl]
    db $76
    ld h, [hl]
    add d
    ld h, [hl]
    add [hl]
    ld h, [hl]
    sub e
    ld h, [hl]
    sub a
    ld h, [hl]
    and b
    ld h, [hl]
    and [hl]
    ld h, [hl]
    xor c
    ld h, [hl]
    xor h
    ld h, [hl]
    or e
    ld h, [hl]
    or a
    ld h, [hl]
    cp e
    ld h, [hl]
    cp a
    ld h, [hl]
    add $66
    ret nc

    ld h, [hl]
    call nc, $de66
    ld h, [hl]
    jp hl


    ld h, [hl]
    pop af
    ld h, [hl]
    ld sp, hl
    ld h, [hl]
    db $fd
    ld h, [hl]
    ld b, d
    ld h, d
    add hl, de
    ld h, a
    rra
    ld h, a
    ld [hl+], a
    ld h, a
    dec h
    ld h, a
    jr z, @+$69

    inc l
    ld h, a
    jr nc, jr_01e_6268

    inc [hl]
    ld h, a
    jr c, jr_01e_626c

    jr c, jr_01e_626e

    ccf
    ld h, a
    ccf
    ld h, a
    ld b, a
    ld h, a
    ld b, a
    ld h, a
    ld c, [hl]
    ld h, a
    ld c, [hl]
    ld h, a
    ld d, [hl]
    ld h, a
    ld d, [hl]
    ld h, a
    ld e, l
    ld h, a
    ld e, l
    ld h, a
    ld h, h
    ld h, a
    ld h, h
    ld h, a

jr_01e_621f:
    ld l, e
    ld h, a
    ld [hl], d
    ld h, a
    ld a, c
    ld h, a
    add b
    ld h, a
    adc e
    ld h, a
    dec b
    ld h, a
    ld de, $1567
    ld h, a
    add a
    ld h, a
    add hl, bc
    ld h, a
    dec c
    ld h, a
    adc [hl]
    ld h, a
    inc e
    ld h, a
    sub c
    ld h, a
    sub l
    ld h, a
    ccf
    ld h, d
    ret c

    rst $38
    rst $38
    ld [$0100], sp
    rst $38
    ld [$0301], sp
    rst $38
    dec b
    ld [bc], a
    ld bc, $0205
    ld bc, $04ff
    inc bc
    ld [bc], a
    inc b
    inc bc
    ld [bc], a
    rst $38
    ld b, [hl]
    inc b
    inc b
    rst $38
    ld [$0100], sp
    inc b
    dec b
    ld d, d
    rst $38
    ld b, $06
    ld [bc], a
    ld b, [hl]
    rst $38

jr_01e_6268:
    ld de, $06ff
    rlca

jr_01e_626c:
    ld [bc], a
    db $10

jr_01e_626e:
    rst $38
    cpl
    rst $38
    ld b, $08
    ld [bc], a
    db $fd
    rst $38
    ld b, [hl]
    rst $38
    dec hl
    db $fc
    rst $38
    rst $38
    ld b, $09
    rrca
    rst $38
    ld [$2a0a], sp
    rst $38
    ld b, $0b
    ld a, [hl+]
    rst $38
    inc b
    inc c
    ld d, $ff
    ld b, [hl]
    dec c
    jr jr_01e_62d6

    dec c
    jr @+$48

    dec c
    jr @+$01

    cp $0e
    inc b
    rst $38
    ld d, $ff
    ld b, [hl]
    rrca
    db $10
    ld b, $ff
    ld [bc], a
    rst $38
    ld b, [hl]
    db $10
    inc b
    rst $38
    ld b, [hl]
    ld de, $db10
    rst $38
    rst $38
    ld b, [hl]
    ld [de], a
    inc b
    db $dd
    rst $38
    rst $38
    inc b
    inc de
    inc hl
    inc b
    inc de
    inc hl
    rst $38
    ld b, $14
    ld [bc], a
    rst $38
    ld bc, $1615
    ld [$01ff], sp
    rst $38
    ld c, b
    ld d, $05
    rst $38
    ld [$0117], sp
    ld [$0117], sp
    rst $38
    ld b, [hl]
    jr jr_01e_62d7

    rst $38
    ld b, [hl]
    add hl, de

jr_01e_62d6:
    inc b

jr_01e_62d7:
    rst $38
    cp $1a
    ld b, [hl]
    rst $38
    inc b
    rst $38
    ld b, [hl]
    dec de
    jr z, @+$01

    ld b, [hl]
    inc e
    dec b
    rst $38
    ld b, $1d
    ld b, l
    ld b, [hl]
    rst $38
    dec b
    rst $38
    ld [bc], a
    ld e, $46
    ld [bc], a
    rst $38
    ld b, [hl]
    rst $38
    ld b, d
    rra
    dec b
    ld b, d
    rst $38
    dec b
    ld b, d
    rst $38
    dec b
    ld b, d
    rst $38
    dec b
    ld b, d
    rst $38
    dec b
    rst $38
    ld a, [c]
    ld c, b
    pop af
    rst $38
    rst $38
    ld a, [c]
    ld c, b
    cp $ff
    cp $ff
    pop af
    rst $38
    rst $38
    inc b
    ld [hl+], a
    inc hl
    inc b
    ld [hl+], a
    inc hl
    inc b
    ld [hl+], a
    inc hl
    rst $38
    ld a, [c]
    ld c, b
    cp $23
    pop af
    rst $38
    rst $38
    ld b, [hl]
    inc h
    inc b
    rst $38
    ldh a, [rOBP0]
    ld b, $ff
    dec l
    db $fc
    rst $38
    ld a, [c]
    rst $38
    cp $25
    pop af
    rst $38
    rst $38
    ld a, [c]
    add h
    pop hl
    rst $38
    pop af
    add h
    pop hl
    rst $38
    ld a, [c]
    add h
    pop hl
    rst $38
    pop af
    add h
    rst $38
    ld b, $27
    nop
    rst $38
    dec b
    jr z, jr_01e_634c

    dec b

jr_01e_634c:
    jr z, jr_01e_634f

    rst $38

jr_01e_634f:
    inc bc
    add hl, hl
    ld bc, $fdff
    ld c, b
    cp $2a
    cp $2a
    db $fc
    rst $38
    rst $38
    ld [$022b], sp
    rst $38
    ld b, [hl]
    inc l
    ld [de], a
    rst $38
    ld b, [hl]
    dec l
    dec d
    ld b, [hl]
    dec l
    dec d
    ld b, [hl]
    dec l
    dec d
    rst $38
    ld b, [hl]
    ld l, $12
    ld d, b
    rst $38
    ld b, b
    ld d, b
    rst $38
    ld b, b
    rst $38
    ld b, $2f
    ld sp, $46ff
    dec l
    dec d
    ld b, [hl]
    dec l
    dec d
    ld b, [hl]
    rrca
    db $10
    ld b, [hl]
    rst $38
    dec b
    rst $38
    db $fd
    ld c, b
    cp $2a
    cp $2a
    db $fc
    rst $38
    rst $38
    ld b, [hl]
    ld [hl-], a
    inc de
    ld b, [hl]
    ld [hl-], a
    inc d
    rst $38
    ld b, [hl]
    inc sp
    ld de, $46ff
    inc [hl]
    rra
    ld b, [hl]
    inc [hl]
    inc c
    ld b, [hl]
    inc [hl]
    dec c
    rst $38
    ldh a, [rIE]
    ld a, [$fc38]
    rst $38
    rst $38
    ld b, $36
    inc l
    rst $38
    ld b, $37
    ld a, [de]
    ld b, $37
    ld a, [de]
    rst $38
    ld a, [$0638]
    scf
    ld a, [de]
    rst $38
    inc bc
    add hl, sp
    ld l, $10
    rst $38
    cpl
    rst $38
    inc b
    ld a, [hl-]
    jr c, jr_01e_63ce

    scf
    jr c, @+$01

    inc bc

jr_01e_63ce:
    dec sp
    ld l, $f8
    rst $38
    rst $38
    ld [de], a
    inc a
    dec [hl]
    rst $38
    inc bc
    dec a
    ld l, $e1
    rst $38
    pop hl
    rst $38
    rst $38
    db $fd
    ld c, b
    ld [c], a
    rst $38
    ld [bc], a
    ld a, $2e
    cp $ff
    cp $ff
    ld b, [hl]
    inc b
    inc b
    db $fc
    rst $38
    rst $38
    ld [$013f], sp
    rst $38
    ld b, [hl]
    ld b, b
    inc b
    rst $38
    db $f4
    ld b, c
    ld b, $ff
    ld bc, $ffdd
    rst $38
    db $f4
    ld b, d
    ld b, [hl]
    rst $38
    inc b
    db $dd
    rst $38
    rst $38
    db $f4
    ld b, e
    ld b, [hl]
    rst $38
    inc b
    db $dd
    rst $38
    rst $38
    sbc $ff
    ld b, c
    adc e
    ld c, [hl]
    rst $18
    rst $38
    db $f4
    rst $38
    ld b, d
    ld b, h
    ld c, a
    pop hl
    rst $38
    pop hl
    rst $38
    db $dd
    rst $38
    ld b, c
    ld b, h
    ld d, b
    call c, $fbff
    rst $38
    rst $38
    ld a, [c]
    ld c, b
    pop af
    rst $38
    ld b, [hl]
    ld b, $04
    rst $38
    ldh a, [rDMA]
    ld b, $ff
    ld hl, $ff06
    ld [hl+], a
    db $fc
    rst $38
    rst $38
    ldh a, [rBGP]
    cp $ff
    ld b, $ff
    ld hl, $ff06
    ld [hl+], a
    cp $ff
    db $fc
    rst $38
    rst $38
    ld b, [hl]
    ld c, b
    dec de
    ld d, l
    ld c, l
    inc e
    rst $38
    ldh a, [rOBP1]
    ld [c], a
    rst $38
    db $fc
    rst $38
    rst $38
    rst $20
    ld c, d
    ld b, c
    add b
    ld b, h
    ld bc, $160c
    rst $38
    ld b, $4b
    ld l, $06
    rst $38
    ld bc, $06ff
    ld c, h
    ld [hl], $ff
    ld b, $4d
    ld [hl], $ff
    ld b, $4e
    ld [hl], $ff
    ldh a, [rVBK]
    and $ff
    db $fc
    rst $38
    rst $38
    ld [$3750], sp
    rst $38
    ld b, [hl]
    ld d, c
    rra
    ld b, [hl]
    rst $38
    inc c
    ld b, [hl]
    rst $38
    dec c
    ld b, [hl]
    rst $38
    ld c, $ff
    ld b, [hl]
    ld d, d
    inc c
    ld b, [hl]
    rst $38
    dec c
    ld b, [hl]
    rst $38
    ld c, $ff
    ld b, d
    ld d, e
    add hl, hl
    rst $38
    ld b, c
    ld d, h
    add hl, hl
    ld b, c
    ld d, h
    add hl, hl
    rst $38
    ld b, d
    ld d, l
    add hl, hl
    ld [bc], a
    rst $38
    inc hl
    inc b
    rst $38
    inc hl
    rst $38
    db $fd
    ld d, [hl]
    cp $ff
    ld b, [hl]
    rst $38
    dec hl
    cp $ff
    ld b, d
    ld d, h
    add hl, hl
    db $fc
    rst $38
    rst $38
    inc b
    ld d, a
    jr nc, @+$01

    ei
    ld e, b
    ei
    ld e, b
    rst $38
    cp $59
    ei
    rst $38
    cp $59
    ei
    rst $38
    rst $38
    ld b, [hl]
    ld e, d
    inc b
    rst $30
    rst $38
    rst $38
    ld a, [$4638]
    ld e, e
    inc d
    rst $38
    ld hl, sp+$5c
    rst $38
    ld hl, sp+$5d
    ret c

    rst $38
    rst $38
    ld hl, sp+$5e
    rst $38
    ldh a, [$5f]
    ld b, [hl]
    rst $38
    ld b, e
    cp $ff
    db $fc
    rst $38
    rst $38
    ldh a, [$60]
    db $fc
    rst $38
    rst $38
    db $f4
    ld h, c
    ld b, [hl]
    rst $38
    inc b
    db $dd
    rst $38
    rst $38
    ld b, $62
    ld bc, $eeff
    ld h, e
    db $ed
    rst $38
    rst $38
    ld hl, sp+$5c
    ret c

    rst $38
    rst $38
    ld b, [hl]
    ld h, l
    ld hl, $6546
    ld [hl+], a
    rst $38
    ld b, [hl]
    ld h, [hl]
    ld [de], a
    rst $38
    db $fd
    rst $38
    pop hl
    rst $38
    pop hl
    rst $38
    cp $ff
    cp $ff
    db $fc
    rst $38
    jp c, $dd67

    rst $38
    ld b, [hl]
    ld l, a
    inc sp
    rst $38
    di
    ld l, b
    ldh a, [rIE]
    ld [c], a
    rst $38
    db $fc
    rst $38
    rst $38
    ldh a, [rBCPD]
    ld b, [hl]
    rst $38
    ld b, e
    cp $ff
    db $fc
    rst $38
    rst $38
    ldh a, [rOCPS]
    ld [c], a
    rst $38
    ld [$fcff], a
    rst $38
    rst $38
    ld b, [hl]
    ld l, e
    jr z, jr_01e_654d

    rst $38
    ld a, [bc]
    ld sp, hl
    rst $38

jr_01e_654d:
    pop hl
    rst $38
    pop hl
    rst $38
    db $fd
    rst $38
    pop hl
    rst $38
    pop hl
    rst $38
    pop hl
    rst $38
    pop hl
    rst $38
    pop hl
    rst $38
    pop hl
    rst $38
    ld sp, hl
    rst $38
    pop hl
    rst $38
    db $fc
    rst $38
    rst $38
    db $fd
    ld l, h
    ld b, [hl]
    rst $38
    ld a, $fc
    rst $38
    rst $38
    ldh a, [$6e]
    or $ff
    ld b, $ff
    ld d, c
    db $fc
    rst $38
    db $dd
    rst $38
    rst $38
    ldh a, [$6e]
    ld b, $ff
    ld b, e
    cp $ff
    db $fc
    rst $38
    rst $38
    ld b, [hl]
    ld l, a
    inc sp
    ld b, [hl]
    ld l, a
    inc sp
    rst $38
    ldh a, [rIE]
    ld b, [hl]
    ld [hl], b
    inc sp
    ld b, [hl]
    ld [hl], b
    inc sp
    db $fc
    rst $38
    rst $38
    ld sp, hl
    rst $38
    ld a, [$fc38]
    rst $38
    rst $38
    db $fd
    rst $38
    ld b, [hl]
    ld [hl], d
    inc sp
    ld b, [hl]
    ld [hl], d
    inc sp
    db $fc
    rst $38
    rst $38
    ld [c], a
    ld [hl], e
    rst $38
    ld b, [hl]
    ld [hl], h
    inc b
    rst $38
    ld a, [c]
    add h
    pop hl
    rst $38
    pop af
    add h
    pop hl
    rst $38
    ld a, [c]
    add h
    pop hl
    rst $38
    pop af
    add h
    rst $38
    ld [$0176], sp
    rst $38
    ld b, e
    ld [hl], a
    inc [hl]
    rst $38
    ld b, h
    ld a, b
    ld b, c
    ld b, h
    ld a, b
    ld b, d
    rst $38
    ld b, [hl]
    ld a, e
    inc d
    rst $38
    ld sp, hl
    ld c, b
    ld b, [hl]
    ld a, d
    add hl, de
    db $fc
    rst $38
    rst $38
    ld b, [hl]
    ld a, e
    inc de
    ld b, [hl]
    ld a, e
    inc d
    rst $38
    ld [$027c], sp
    rst $38
    ld b, [hl]
    ld a, l
    rra
    ld b, [hl]
    rst $38
    jr nz, jr_01e_6631

    rst $38
    jr nz, jr_01e_6634

    rst $38
    inc c
    ld b, [hl]
    rst $38
    dec c
    rst $38
    or $48
    ld b, $37
    ld a, [de]
    ld [$02ff], sp
    rst $30
    rst $38
    rst $38
    ld [$2a7f], sp
    ld b, $83
    inc hl
    ld b, $83
    inc hl
    rst $38
    ld b, e
    add b
    ccf
    rst $38
    ld b, [hl]
    add c
    dec b
    rst $38
    ld b, h
    add d
    inc b
    rst $38
    ld b, $83
    inc hl

Jump_01e_6618:
    ld b, $83
    inc hl
    ld b, $83
    inc hl
    rst $38
    ld [$2584], sp
    ld [$2584], sp
    rst $38
    ld [$0185], sp
    rst $38
    push hl
    ld c, b
    ld [$4c86], sp
    ldh a, [rIE]

jr_01e_6631:
    ld [c], a
    rst $38
    db $fc

jr_01e_6634:
    rst $38
    db $dd
    rst $38
    rst $38
    ld b, [hl]
    add a
    inc b
    rst $38
    db $fd
    ld c, b
    cp $88
    cp $ff
    db $fc
    rst $38
    rst $38
    ld hl, sp-$77
    db $fd
    adc c
    ld [$0289], sp
    db $fc
    rst $38
    rst $38
    ld b, [hl]
    adc d
    add hl, de
    rst $38
    ld b, e
    adc e
    ld b, c
    dec b
    rst $38
    ld d, l
    rst $38
    ld [$028c], sp
    cp $ff
    ld b, $ff
    ld hl, $ff06
    ld [hl+], a
    cp $ff
    rst $38
    ld b, $8d
    ld [de], a
    rst $38
    xor $8e
    db $ed
    rst $38
    ld b, [hl]
    add a
    inc b
    db $dd
    rst $38
    rst $38
    ld b, [hl]
    adc a
    ld hl, $8f44
    ld [hl+], a
    ld [$47ff], sp
    add sp, -$01
    rst $38
    ld d, $90
    dec [hl]
    rst $38
    ld b, $91
    rla
    ld b, $91
    rla
    ld b, $91
    rla
    ld b, $02
    ld [bc], a
    rst $38
    ld b, $92
    ld [hl], $ff
    ldh a, [rOBP0]
    cp $88
    cp $ff
    db $fc
    rst $38
    rst $38
    ld b, $2f
    ld sp, $5cd8
    rst $38
    db $eb
    sub l
    rst $38
    jp hl


    sub [hl]
    rst $38
    ld b, [hl]
    sub a
    dec b
    ld b, $ff
    ld a, [hl+]
    rst $38
    ld b, e
    sbc b
    inc [hl]
    rst $38
    inc b
    sbc c
    rrca
    rst $38
    ld b, $9a
    ld [bc], a
    rst $38
    db $10
    sbc e
    ld a, [hl-]
    db $10
    sbc e
    ld a, [hl-]
    rst $38
    inc b
    sbc h
    dec e
    inc bc
    sbc h
    ld e, $46
    sbc l
    inc b
    rst $38
    ld b, $9d
    ld [bc], a
    rst $38
    ldh a, [$9e]
    ld b, [hl]
    rst $38
    ld b, e
    cp $ff
    db $fc
    rst $38
    rst $38
    cp $9f
    ld b, [hl]
    rst $38
    ld hl, $ff46
    ld [hl+], a
    cp $ff
    rst $38
    cp $a0
    ld b, [hl]
    rst $38
    ld c, l
    cp $ff
    rst $38
    db $fd
    ld c, b
    ld b, [hl]
    and c
    inc b
    db $fc
    rst $38
    rst $38
    ld b, $a2
    rrca
    rst $38
    db $f4
    and e
    ld [$47ff], sp
    reti


    rst $38
    rst $38
    inc bc
    rst $38
    ld b, $ff
    inc bc
    rst $38
    rlca
    rst $38
    ld [bc], a
    rst $38
    ld [$04ff], sp
    rst $38
    add hl, bc
    rst $38
    inc b
    rst $38
    ld a, [bc]
    rst $38
    call c, $ffff
    rst $18
    rst $38
    rst $38
    db $dd
    rst $38
    rst $38
    push af
    rst $38
    rst $38
    db $e4
    rst $38
    rst $38
    add [hl]
    rst $38
    ld c, b
    rst $38
    add h
    rst $38
    ld c, c
    rst $38
    add [hl]
    rst $38
    ld c, d
    rst $38
    add [hl]
    rst $38
    ld c, e
    rst $38
    ldh a, [rIE]
    ld [c], a
    rst $38
    db $fc
    rst $38
    rst $38
    ldh a, [rIE]
    ld b, [hl]
    rst $38
    ld b, e
    db $fc
    rst $38
    rst $38
    ld sp, hl
    rst $38
    ld [c], a
    rst $38
    db $fc
    rst $38
    rst $38
    ld sp, hl
    rst $38
    ld b, [hl]
    rst $38
    ld b, e
    db $fc
    rst $38
    rst $38
    ldh a, [rIE]
    db $ec
    rst $38
    db $fc
    rst $38
    rst $38
    inc b
    inc de
    inc h
    inc b
    inc de
    inc h
    rst $38
    ld [$2713], sp
    ld [$2713], sp
    rst $38
    db $10
    sbc e
    ld a, [hl-]
    db $10
    sbc e
    ld a, [hl-]
    rst $38
    db $10
    sbc e
    dec sp
    db $10
    sbc e
    dec sp
    rst $38
    ld [$2584], sp
    ld [$2584], sp
    rst $38
    ld [$2684], sp
    ld [$2684], sp
    rst $38
    inc bc
    rst $38
    dec bc
    rst $38
    or $5a
    rst $38
    ei
    rst $38
    rst $38
    inc bc
    adc e
    ld d, e
    rst $38
    inc bc
    adc e
    ld d, h
    rst $38
    ld [hl], d
    ld l, c
    db $76
    ld l, c
    ld a, l
    ld l, c
    add a
    ld l, c
    ld b, l
    ld l, b
    ld c, a
    ld l, b
    sub a
    ld l, b
    ld [hl], l
    ld l, b
    ld d, e
    ld l, b
    cp c
    ld l, b
    add $68
    reti


    ld l, b
    sub h
    ld l, c
    sbc [hl]
    ld l, c
    or c
    ld l, c
    ld c, h
    ld l, d
    sub [hl]
    ld l, d
    ld [$5668], a
    ld l, c
    adc $6a
    pop hl
    ld l, d
    rla
    ld l, e
    ld [hl], c
    ld l, d
    ld e, $6b
    dec hl
    ld l, e
    ld c, e
    ld l, e
    ld [hl], b
    ld l, e
    and c
    ld l, e
    xor [hl]
    ld l, e
    cp b
    ld l, e
    and $6b
    call $ea69
    ld l, e
    pop af
    ld l, e
    ei
    ld l, e
    call z, $d36c
    ld l, h
    jp c, $e16c

    ld l, h
    db $fc
    ld l, h
    inc bc
    ld l, l
    ld h, a
    ld l, h
    cp a
    ld l, h
    rrca
    ld l, c
    ld sp, $1d69
    ld l, h
    db $dd
    ld l, c
    ld [$156a], sp
    ld l, d
    xor a
    ld l, d
    dec c
    ld l, l
    rla
    ld l, l
    ld e, c
    ld l, l
    sbc c
    ld l, l
    and [hl]
    ld l, l
    cp a
    ld l, l
    sbc $6d
    jr nc, jr_01e_6879

    add sp, $6c
    ld a, [c]
    ld l, h
    ld a, [hl+]
    ld l, l
    ld b, b
    ld l, l
    rrca
    ld l, [hl]
    ld b, [hl]
    ld l, [hl]
    jr c, jr_01e_6886

    db $fd
    ld l, d
    dec c
    ld l, e
    and d
    ld l, [hl]
    ld a, l
    ld l, [hl]
    xor h
    ld l, [hl]
    cp c
    ld l, [hl]
    call z, $d66e
    ld l, [hl]
    jp hl


    ld l, [hl]
    or $6e
    ld a, [$046e]
    ld l, a
    dec e
    ld l, a
    inc [hl]
    ld l, h
    jr c, jr_01e_68a5

    ld c, [hl]
    ld l, h
    jr nc, jr_01e_68ac

    ld b, e
    ld l, a
    ld e, c
    ld l, a
    ld a, [hl]
    ld l, a
    and $68
    ld b, e
    ld [bc], a
    ld a, [de]
    nop
    ld [bc], a
    stop
    ld [bc], a
    inc bc
    nop
    ld b, c
    ld [bc], a
    stop
    dec bc
    inc bc
    jr nc, jr_01e_6857

jr_01e_6857:
    inc bc
    ld b, h
    nop
    inc bc
    sub h
    nop
    inc bc
    ld h, b
    nop
    inc bc
    halt
    inc bc
    sbc a
    nop
    inc bc
    adc l
    nop
    inc bc
    and b
    nop
    inc bc
    ld a, [de]
    nop
    inc bc
    and c
    nop
    inc bc
    inc [hl]
    nop
    dec bc
    inc bc
    jr nc, jr_01e_6879

jr_01e_6879:
    inc bc
    and d
    nop
    inc bc
    ld sp, $0300
    and e
    nop
    inc bc
    ld [hl-], a
    nop
    inc bc

jr_01e_6886:
    and h
    nop
    inc bc
    sub d
    nop
    inc bc
    and l
    nop
    inc bc
    dec d
    nop
    inc bc
    and [hl]
    nop
    inc bc
    inc [hl]
    nop
    dec bc
    inc bc
    jr nc, jr_01e_689b

jr_01e_689b:
    inc bc
    and d
    nop
    inc bc
    sub e
    nop
    inc bc
    ld h, c
    nop
    inc bc

jr_01e_68a5:
    ld [hl], e
    nop
    inc bc
    and a
    nop
    inc bc
    inc sp

jr_01e_68ac:
    nop
    inc bc
    xor b
    nop
    inc bc
    ld c, $00
    inc bc
    xor c
    nop
    inc bc
    inc [hl]
    nop
    inc b
    inc bc
    ld hl, $0404
    ld hl, $0304
    ld hl, $0504
    ld hl, $4604
    ld b, $1b
    nop
    rlca
    dec de
    nop
    ld [$0036], sp
    add hl, bc
    ld [hl], $00
    ld a, [bc]
    dec d
    nop
    ld a, [bc]
    dec d
    nop
    inc b
    ld bc, $002d
    inc bc
    cpl
    nop
    inc bc
    dec [hl]
    nop
    inc bc
    ld c, l
    nop
    ld b, c
    ld bc, $009d
    ld c, h
    dec bc
    ld h, $00
    inc c
    ld h, $00
    dec bc
    ld h, $00
    inc c
    ld h, $00
    dec bc
    jr z, jr_01e_68fa

jr_01e_68fa:
    inc c
    jr z, jr_01e_68fd

jr_01e_68fd:
    dec bc
    jr z, jr_01e_6900

jr_01e_6900:
    inc c
    jr z, jr_01e_6903

jr_01e_6903:
    dec bc
    daa
    nop
    inc c
    daa
    nop
    dec bc
    daa
    nop
    inc c
    daa
    nop
    ld c, e
    dec c
    inc bc
    inc bc
    ld c, $03
    inc bc
    rrca
    inc bc
    nop
    dec c
    ld de, $0d00
    ld de, $0d00
    scf
    nop
    dec c
    scf
    nop
    db $10
    ld hl, $1000
    ld hl, $1100
    dec de
    nop
    ld de, $001b
    ld c, h
    ld [de], a
    ld bc, $1200
    rrca
    nop
    ld [de], a
    dec de
    nop
    ld [de], a
    dec h
    nop
    inc de
    jr c, jr_01e_6941

jr_01e_6941:
    inc de
    jr c, @+$04

    inc d
    jr c, jr_01e_6947

jr_01e_6947:
    inc d
    jr c, @+$04

    dec d
    jr c, jr_01e_694d

jr_01e_694d:
    dec d
    jr c, jr_01e_6950

jr_01e_6950:
    ld d, $38
    nop
    ld d, $38
    nop
    ld l, c
    rla
    jr nc, jr_01e_695a

jr_01e_695a:
    rla
    add hl, sp
    nop
    rla
    ld a, [hl-]
    nop
    rla
    dec sp
    nop
    rla
    inc a
    nop
    rla
    dec a
    nop
    rla
    ld a, $00
    rla
    ccf
    nop
    rla
    rra
    nop
    ld b, c
    ld bc, $0017
    ld b, d
    ld bc, $000f
    ld bc, $001d
    ld b, e
    ld bc, $0012
    ld bc, $0015
    ld bc, $001c
    ld b, h
    ld bc, $000b
    ld bc, $0011
    ld bc, $0018
    ld bc, $001d
    ld b, e
    inc c
    jr nz, jr_01e_6998

jr_01e_6998:
    inc c
    ld hl, $0c00
    inc hl
    nop
    ld b, [hl]
    inc c
    jr nz, jr_01e_69a4

    inc c
    dec d

jr_01e_69a4:
    nop
    inc c
    ld hl, $0c02
    rla
    nop
    inc c
    inc hl
    ld [bc], a
    inc c
    add hl, de
    nop
    ld c, c
    inc c
    jr nz, jr_01e_69b7

    inc c
    dec d

jr_01e_69b7:
    ld [bc], a
    inc c
    rlca
    nop
    inc c
    ld hl, $0c02
    rla
    ld [bc], a
    inc c
    add hl, bc
    nop
    inc c
    inc hl
    ld [bc], a
    inc c
    add hl, de
    ld [bc], a
    inc c
    inc c
    nop
    add l
    inc c
    jr nc, jr_01e_69d4

    inc c
    ld b, b
    inc bc

jr_01e_69d4:
    inc c
    ld b, c
    inc bc
    inc c
    ld b, d
    inc bc
    inc c
    ld hl, $2e00
    jr jr_01e_6a23

    ld [bc], a
    ld [hl], l
    ld d, d
    inc b
    add hl, de
    ld b, e
    ld [bc], a
    ld [hl], l
    ld h, e
    inc b
    ld a, [de]
    ld b, e
    ld [bc], a
    ld [hl], l
    ld c, l
    inc b
    dec de
    ld b, e
    ld [bc], a
    ld [hl], l
    sub a
    inc b
    inc e
    ld b, e
    ld [bc], a
    ld [hl], l
    sbc b
    inc b
    dec e
    ld b, e
    ld [bc], a
    ld [hl], l
    ld e, b
    inc b
    ld e, $43
    ld [bc], a
    ld [hl], l
    dec de
    nop
    ld b, h
    rra
    inc h
    nop
    jr nz, jr_01e_6a2e

    nop
    ld hl, $001a
    ld [hl+], a
    dec d
    nop
    ld d, d
    inc hl
    nop
    ld [bc], a
    inc hl
    ld [bc], a
    ld [bc], a
    inc hl
    inc b
    nop
    inc hl
    rlca
    ld [bc], a
    inc hl

jr_01e_6a23:
    ld [bc], a
    ld [bc], a
    inc hl
    inc b
    nop
    inc hl
    ld c, $02
    inc hl
    ld [bc], a
    ld [bc], a

jr_01e_6a2e:
    inc hl
    inc c
    nop
    dec h
    rlca
    nop
    dec h
    ld c, $00
    dec h
    dec d
    nop
    inc h
    inc h
    ld [bc], a
    inc hl
    inc e
    ld [bc], a
    inc hl
    inc hl
    nop
    inc hl
    ld hl, $2402
    jr z, jr_01e_6a49

jr_01e_6a49:
    inc h
    jr z, jr_01e_6a4c

jr_01e_6a4c:
    ld c, h
    ld h, $0e
    ld [bc], a
    ld h, $16
    ld [bc], a
    ld h, $1c
    nop
    daa
    ld c, $02
    daa
    ld d, $02
    daa
    inc e
    nop
    jr z, jr_01e_6a6f

    ld [bc], a
    jr z, jr_01e_6a7a

    ld [bc], a
    jr z, jr_01e_6a83

    nop
    add hl, hl

jr_01e_6a69:
    ld c, $02
    add hl, hl
    ld d, $02
    add hl, hl

jr_01e_6a6f:
    inc e
    nop
    ld c, h
    ld a, [hl+]
    dec b
    nop
    dec hl
    dec b
    ld [bc], a
    dec hl
    inc c

jr_01e_6a7a:
    ld [bc], a
    ld a, [hl+]
    ld de, $2b04
    ld de, $2b02
    rla

jr_01e_6a83:
    ld [bc], a
    ld a, [hl+]
    dec de
    inc b
    dec hl
    dec de
    ld [bc], a
    dec hl
    jr nz, jr_01e_6a8f

    ld a, [hl+]
    cpl

jr_01e_6a8f:
    inc b
    inc l
    nop
    ld [bc], a
    inc l
    nop
    nop
    adc b
    dec l
    ld b, h
    nop
    ld l, $45
    nop
    dec l
    ld b, [hl]
    nop
    ld l, $47
    nop
    dec l
    ld c, b
    nop
    ld l, $49
    nop
    dec l
    cpl
    nop
    ld l, $1a
    nop
    ld a, [hl+]
    cpl
    ld b, [hl]
    nop
    cpl
    ld c, d
    nop
    cpl
    ld c, e
    nop
    cpl
    ld c, h
    nop
    cpl
    ld c, l
    nop
    cpl
    ld c, [hl]
    nop
    cpl
    ld c, a
    nop
    cpl
    ld d, b
    nop
    cpl
    ld l, $00
    cpl
    ld d, c
    nop
    add [hl]
    jr nc, jr_01e_6b02

    nop
    jr nc, jr_01e_6b06

    nop
    jr nc, jr_01e_6a69

    nop
    jr nc, jr_01e_6ae8

    nop
    jr nc, @+$11

    nop
    jr nc, @+$12

    nop
    ld c, c
    jr nc, jr_01e_6af4

    nop
    jr nc, jr_01e_6af7

    inc bc

jr_01e_6ae8:
    ld sp, $041c
    ld sp, $0421
    ld sp, $0026
    jr nc, jr_01e_6b03

    ld [bc], a

jr_01e_6af4:
    ld sp, $041d

jr_01e_6af7:
    ld sp, $0422
    ld sp, $0027
    add l
    inc bc
    ld sp, $0300

jr_01e_6b02:
    ld [hl-], a

jr_01e_6b03:
    nop
    inc bc
    sub d

jr_01e_6b06:
    nop
    inc bc
    ld c, $00
    inc bc
    stop
    ld b, e
    ld c, b
    ld [$4900], sp
    ld [$5a00], sp
    ld [$2200], sp
    dec [hl]
    ld d, d
    nop
    dec [hl]
    ld d, e
    nop
    ld b, h
    ld [hl], $54
    nop
    ld [hl], $55
    nop
    scf
    ld d, [hl]
    nop
    scf
    ld d, a
    nop
    and h
    ld [hl], $54
    nop
    ld [hl], $55
    nop
    scf
    ld d, [hl]
    nop
    scf
    ld d, a
    nop
    ld b, [hl]
    rla
    ld d, h
    nop
    rla
    ld d, l
    nop
    rla
    ld c, $00
    rla
    ld d, [hl]
    nop
    rla
    ld d, a
    nop
    rla
    inc de
    nop
    adc h
    jr c, @+$33

    nop
    add hl, sp
    ld sp, $3800
    ld [hl-], a
    nop
    add hl, sp
    ld [hl-], a
    nop
    jr c, @-$6c

    nop
    add hl, sp
    sub d
    nop
    jr c, jr_01e_6b6e

    nop
    add hl, sp
    ld c, $00
    jr c, jr_01e_6b75

    nop
    add hl, sp
    rrca
    nop
    jr c, @+$12

    nop
    add hl, sp

jr_01e_6b6e:
    stop
    ld d, b
    ld a, [hl-]
    ld [$3b00], sp

jr_01e_6b75:
    ld [$3c00], sp
    ld [$3d00], sp
    ld [$3e00], sp
    ld [$3f00], sp
    ld [$3e00], sp
    ld [$3f00], sp
    ld [$3a00], sp
    dec bc
    nop
    dec sp
    dec bc
    nop
    inc a
    dec bc
    nop
    dec a
    dec bc
    nop
    ld a, $0b
    nop
    ccf
    dec bc
    nop
    ld a, $0b
    nop
    ccf
    dec bc
    nop
    add h
    ld b, b
    ld sp, $4000
    ld [hl-], a
    nop
    ld b, b
    sub d
    nop
    ld b, b
    dec d
    nop
    ld b, e
    ld b, c
    ld e, b
    nop
    ld b, c
    ld e, c
    nop
    ld b, c
    ld hl, $af00
    inc h
    sbc d
    nop
    inc hl
    dec de
    ld [bc], a
    inc h
    ld [hl+], a
    nop
    inc hl
    ld d, $02
    inc hl
    dec e
    ld [bc], a
    inc h
    sbc b
    nop
    dec h
    inc l
    inc b
    dec h
    ld a, [hl+]
    inc b
    dec h
    sbc c
    inc b
    dec h
    ld h, d
    inc b
    dec h
    sbc c
    inc b
    dec h
    ld h, d
    inc b
    dec h
    sbc c
    inc b
    dec h
    ld h, d
    inc b
    dec h
    sbc c
    inc bc
    ld bc, $7525
    nop
    ld b, d
    ld b, d
    rlca
    nop
    ld b, e
    rlca
    nop
    ld b, e
    ld b, h
    nop
    nop
    ld b, l
    ld [$4600], sp
    db $10
    ld [bc], a
    adc e
    ld b, a
    stop
    ld b, a
    ld d, [hl]
    nop
    ld b, a
    rlca
    nop
    ld b, a
    xor d
    nop
    ld b, a
    xor e
    nop
    ld b, a
    xor h
    nop
    ld b, a
    xor l
    nop
    ld b, a
    xor [hl]
    nop
    ld b, a
    xor a
    nop
    ld b, a
    adc c
    nop
    ld b, a
    or b
    nop
    ld h, [hl]
    ld b, h
    ld h, h
    nop
    ld b, l
    ld h, l
    nop
    ld b, [hl]
    ld h, [hl]
    nop
    ld b, a
    ld h, [hl]
    nop
    ld b, a
    ld h, [hl]
    nop
    ld b, a
    ld h, [hl]
    nop
    ld h, c
    ld b, a
    ld h, a
    nop
    ld b, c
    ld [hl], c
    rrca
    inc bc
    ld b, a
    ld [hl], c
    rrca
    nop
    ld [hl], c
    ld [$7100], sp
    ld bc, $7100
    sub l
    nop
    ld [hl], d
    sub l
    nop
    ld [hl], e
    sub l
    nop
    ld [hl], h
    sub l
    nop
    ld c, b
    ld [hl], h
    sub l
    nop
    ld [hl], e
    sub l
    nop
    ld [hl], d
    sub l
    nop
    ld [hl], c
    sub l
    nop
    ld [hl], c
    ld bc, $7100
    ld [$7100], sp
    rrca
    nop
    ld [hl], c
    ld d, $00
    ld e, l
    ld c, b
    rrca
    nop
    ld c, d
    ld l, b
    inc bc
    ld c, e
    ld a, [hl+]
    inc bc
    ld c, c
    rrca
    nop
    ld c, d
    ld l, b
    inc bc
    ld c, e
    ld a, [hl+]
    nop
    ld c, h
    ld l, d
    inc bc
    ld c, l
    ld l, c
    inc bc
    ld c, c
    ld l, e
    nop
    ld c, h
    ld l, d
    inc bc
    ld c, l
    ld l, c
    nop
    ld c, d
    ld l, b
    inc bc
    ld c, e
    ld a, [hl+]
    inc bc
    ld c, c
    ld l, h
    nop
    ld c, d
    ld l, b
    inc bc
    ld c, e
    ld a, [hl+]
    nop
    ld c, h
    ld l, d
    inc bc
    ld c, l
    ld l, c
    inc bc
    ld c, c
    ld l, l
    nop
    ld c, h
    ld l, d
    inc bc
    ld c, l
    ld a, [hl+]
    nop
    ld c, d
    ld l, b
    inc bc
    ld c, e
    ld a, [hl+]
    inc bc
    ld c, c
    rrca
    nop
    ld c, d
    ld l, b
    inc bc
    ld c, e
    ld a, [hl+]
    nop
    ld c, h
    ld l, d
    inc bc
    ld c, l
    ld a, [hl+]
    inc bc
    ld c, c
    ld l, e
    nop
    ld b, h
    ld c, [hl]
    dec hl
    nop
    ld c, a
    dec hl
    nop
    ld d, b
    dec hl
    nop
    ld d, b
    dec hl
    nop
    ld b, d
    ld d, c
    dec l
    nop
    ld d, c
    ld l, [hl]
    nop
    and d
    ld d, c
    dec l
    nop
    ld d, c
    ld l, [hl]
    nop
    ld h, d
    ld d, d
    ld [hl], c
    nop
    ld d, d
    ld [hl], d
    nop
    ld [bc], a
    ld d, d
    ld bc, $5200
    inc l
    nop
    ld h, e
    ld d, e
    ld [hl], c
    nop
    ld d, e
    ld a, a
    nop
    ld d, e
    add c
    nop
    inc bc
    ld d, e
    ld bc, $5300
    dec d
    nop
    ld d, e
    inc l
    nop
    and d
    ld d, h
    ld bc, $5400
    inc l
    nop
    inc hl
    ld d, l
    ld [hl], e
    inc bc
    ld d, [hl]
    ld [hl], e
    inc bc
    ld d, a
    ld [hl], e
    nop
    ld h, e
    ld b, a
    ld [hl], h
    nop
    ld b, a
    ld b, e
    nop
    ld b, a
    ld [hl], l
    nop
    ld h, $58
    halt
    inc [hl]
    halt
    ld e, b
    halt
    inc [hl]
    halt
    ld e, b
    halt
    inc [hl]
    halt
    ld h, a
    ld e, c
    ld a, c
    inc bc
    ld e, c
    ld a, e
    inc bc
    ld e, c
    ld [hl], a
    inc bc
    ld e, c
    ld a, d
    inc bc
    ld e, c
    ld a, b
    inc bc
    ld e, c
    ld a, h
    inc bc
    ld e, c
    halt
    ld [$4d3a], sp
    nop
    dec sp
    ld c, l
    nop
    inc a
    ld c, l
    nop
    dec a
    ld c, l
    nop
    ld a, $4d
    nop
    ccf
    ld c, l
    nop
    ld a, $4d
    nop
    ccf
    ld c, l
    nop
    dec [hl]
    ld c, b
    ld a, l
    nop
    ld c, c
    ld a, l
    nop
    ld e, d
    ld a, l
    nop
    ld c, b
    jr nc, jr_01e_6d66

jr_01e_6d66:
    ld c, c
    jr nc, jr_01e_6d69

jr_01e_6d69:
    ld e, d
    jr nc, jr_01e_6d6c

jr_01e_6d6c:
    ld c, b
    ld a, [hl]
    nop
    ld c, c
    ld a, [hl]
    nop
    ld e, d
    ld a, [hl]
    nop
    ld c, b
    ld a, a
    nop
    ld c, c
    ld a, a
    nop
    ld e, d
    ld a, a
    nop
    ld c, b
    add b
    nop
    ld c, c
    add b
    nop
    ld e, d
    add b
    nop
    ld c, b
    add c
    nop
    ld c, c
    add c
    nop
    ld e, d
    add c
    nop
    ld c, b
    add d
    nop
    ld c, c
    add d
    nop
    ld e, d
    add d
    nop
    inc h
    ld e, e
    add e
    inc bc
    ld e, h
    add h
    inc bc
    ld e, l
    add l
    inc bc
    ld e, [hl]
    add hl, bc
    nop
    ld c, b
    ld e, a
    ld a, [hl+]
    nop
    ld e, a
    nop
    nop
    ld h, b
    ld a, [hl+]
    nop
    ld h, b
    nop
    nop
    ld h, c
    ld a, [hl+]
    nop
    ld h, c
    nop
    nop
    ld h, d
    ld a, [hl+]
    nop
    ld h, d
    nop
    nop
    ld a, [hl+]
    ld h, e
    adc c
    nop
    ld h, h
    ld [hl], l
    nop
    ld h, e
    halt
    ld h, l
    dec c
    nop
    ld h, l
    add [hl]
    nop
    ld h, l
    ld [de], a
    nop
    ld h, l
    add a
    nop
    ld h, l
    rla
    nop
    ld h, l
    adc b
    nop
    ld h, l
    ld a, [de]
    nop
    ld d, b
    ld h, [hl]
    adc d
    nop
    ld h, [hl]
    inc sp
    nop
    ld h, [hl]
    ld l, $00
    ld h, a
    inc h
    inc bc
    ld h, [hl]
    ld bc, $6604
    db $10
    inc b
    ld h, [hl]
    dec e
    inc b
    ld h, a
    jr z, jr_01e_6dfa

    ld h, [hl]
    ld a, [hl+]
    inc b

jr_01e_6dfa:
    ld h, [hl]
    ld c, $04
    ld h, [hl]
    dec de
    inc b
    ld h, a
    ld h, $03
    ld h, [hl]
    inc bc
    inc b
    ld h, [hl]
    ld [de], a
    inc b
    ld h, [hl]
    ld e, $04
    ld h, a
    add hl, hl
    nop
    sub d
    ld [bc], a
    ld sp, $3400
    ld sp, $0200
    ld sp, $0200
    ld [hl-], a
    nop
    inc [hl]
    ld [hl-], a
    nop
    ld [bc], a
    ld [hl-], a
    nop
    ld [bc], a
    sub d
    nop
    inc [hl]
    sub d
    nop
    ld [bc], a
    sub d
    nop
    ld [bc], a
    ld c, $00
    inc [hl]
    ld c, $00
    ld [bc], a
    ld c, $00
    ld [bc], a
    rrca
    nop
    inc [hl]
    rrca
    nop
    ld [bc], a
    rrca
    nop
    ld [bc], a
    stop
    inc [hl]
    stop
    ld [bc], a
    stop
    ld [hl], d
    ld l, b
    ld c, e
    nop
    ld l, b
    adc h
    nop
    ld l, b
    jr nz, jr_01e_6e50

jr_01e_6e50:
    ld l, b
    inc e
    nop
    ld l, b
    add hl, de
    nop
    ld l, b
    inc d
    nop
    ld l, b
    halt
    ld l, b
    adc l
    nop
    ld l, b
    dec d
    nop
    ld l, b
    stop
    ld l, b
    inc c
    nop
    ld l, b
    ld b, $00
    ld l, b
    adc [hl]
    nop
    ld l, b
    adc a
    nop
    ld l, b
    sub b
    nop
    ld l, b
    ld h, $00
    ld l, b
    inc hl
    nop
    ld l, b
    rra
    nop
    inc l
    ld l, c
    ld c, e
    nop
    ld l, c
    adc h
    nop
    ld l, c
    jr nz, jr_01e_6e87

jr_01e_6e87:
    ld l, c
    inc e
    nop
    ld l, c
    add hl, de
    nop
    ld l, c
    inc d
    nop
    ld l, c
    halt
    ld l, c
    adc l
    nop
    ld l, c
    dec d
    nop
    ld l, c
    stop
    ld l, c
    inc c
    nop
    ld l, c
    ld b, $00
    and e
    ld l, d
    rlca
    nop
    ld l, e
    rrca
    nop
    ld l, h
    rla
    nop
    inc h
    ld l, l
    adc e
    nop
    ld l, l
    add h
    nop
    ld l, l
    ld h, e
    nop
    ld l, l
    adc h
    nop
    ld h, $6d
    adc e
    nop
    ld l, l
    add h
    nop
    ld l, l
    ld h, e
    nop
    ld l, l
    adc h
    nop
    ld l, l
    ld a, [bc]
    nop
    ld l, l
    adc c
    nop
    inc hl
    ld b, $82
    nop
    rlca
    add d
    nop
    ld [$0096], sp
    ld b, $03
    ld b, c
    inc b
    inc bc
    ld c, b
    inc b
    inc b
    ld c, b
    inc b
    inc bc
    ld c, b
    inc b
    dec b
    ld c, b
    inc b
    inc bc
    ld c, b
    inc bc
    inc b
    inc b
    ld c, b
    inc b
    inc bc
    ld c, b
    inc b
    dec b
    ld c, b
    inc b
    inc bc
    ld c, b
    inc bc
    ld bc, $8404
    inc bc
    inc bc
    ld b, $72
    nop
    rlca
    ld [hl], d
    nop
    ld [$0072], sp
    ld l, b
    ld l, a
    jr nc, jr_01e_6f08

jr_01e_6f08:
    ld l, [hl]
    jr nc, jr_01e_6f0b

jr_01e_6f0b:
    ld [hl], b
    jr nc, jr_01e_6f0e

jr_01e_6f0e:
    ld l, [hl]
    jr nc, jr_01e_6f11

jr_01e_6f11:
    ld l, a
    jr nc, jr_01e_6f14

jr_01e_6f14:
    ld l, [hl]
    jr nc, jr_01e_6f17

jr_01e_6f17:
    ld [hl], b
    jr nc, jr_01e_6f1a

jr_01e_6f1a:
    ld l, [hl]
    jr nc, jr_01e_6f1d

jr_01e_6f1d:
    ld h, $32
    ld c, e
    nop
    inc sp
    ld c, a
    nop
    ld [hl-], a
    jr nz, jr_01e_6f27

jr_01e_6f27:
    inc sp
    ld d, $00
    ld [hl-], a
    add hl, de
    nop
    inc sp
    dec c
    nop
    and [hl]
    db $76
    dec de
    nop
    inc [hl]
    dec de
    nop
    db $76
    dec de
    nop
    inc [hl]
    dec de
    nop
    db $76
    dec de
    nop
    inc [hl]
    dec de
    nop
    ld b, a
    ld [hl], a
    dec h
    nop
    ld [hl], a
    sbc e
    nop
    ld [hl], a
    ld a, [de]
    nop
    ld [hl], a
    sbc h
    nop
    ld [hl], a
    cpl
    nop
    ld [hl], a
    ld d, b
    nop
    ld [hl], a
    adc h
    nop
    inc c
    ld a, b
    jr nc, jr_01e_6f5d

jr_01e_6f5d:
    ld a, b
    and d
    nop
    ld a, b
    sub e
    nop
    ld a, b
    ld h, c
    nop
    ld a, b
    ld [hl], e
    nop
    ld a, b
    and a
    nop
    ld a, b
    inc sp
    nop
    ld a, b
    xor b
    nop
    ld a, b
    ld c, $00
    ld a, b
    xor c
    nop
    ld a, b
    inc [hl]
    nop
    ld bc, $009e
    dec bc
    ld a, c
    jr nc, jr_01e_6f82

jr_01e_6f82:
    ld a, c
    and d
    nop
    ld a, c
    sub e
    nop
    ld a, c
    ld h, c
    nop
    ld a, c
    ld [hl], e
    nop
    ld a, c
    and a
    nop
    ld a, c
    inc sp
    nop
    ld a, c
    xor b
    nop
    ld a, c
    ld c, $00
    ld a, c
    xor c
    nop
    ld a, c
    inc [hl]
    nop
    inc de
    ld a, [hl]
    sub h
    ld [hl], b
    cp c
    ld [hl], b
    ld a, [$0b70]
    ld [hl], c
    inc e
    ld [hl], c
    dec l
    ld [hl], c
    ld e, [hl]
    ld [hl], c
    sbc a
    ld [hl], c
    ldh [$71], a
    ld de, $4272
    ld [hl], d
    ld d, e
    ld [hl], d
    ld h, h
    ld [hl], d
    add l
    ld [hl], d
    sub [hl]
    ld [hl], d
    and a
    ld [hl], d
    ret z

    ld [hl], d
    jp hl


    ld [hl], d
    or $72
    rlca
    ld [hl], e
    jr z, jr_01e_703f

    ld e, c
    ld [hl], e
    ld a, d
    ld [hl], e
    adc e
    ld [hl], e
    sub b
    ld [hl], e
    sbc c
    ld [hl], e
    and d
    ld [hl], e
    xor e
    ld [hl], e
    or h
    ld [hl], e
    cp l
    ld [hl], e
    rst $10
    ld [hl], e
    ldh [$73], a
    ld sp, hl
    ld [hl], e
    ld a, [hl+]
    ld [hl], h
    ld [hl], a
    ld [hl], h
    adc b
    ld [hl], h
    sub c
    ld [hl], h
    jp nz, $d374

    ld [hl], h
    add sp, $74
    ld bc, $1275
    ld [hl], l
    inc hl
    ld [hl], l
    inc l
    ld [hl], l
    ld sp, $5275
    ld [hl], l
    ld [hl], e
    ld [hl], l
    add h
    ld [hl], l
    sub l
    ld [hl], l
    sbc d
    ld [hl], l
    or a
    ld [hl], l
    call nc, $d975
    ld [hl], l
    ld a, [c]
    ld [hl], l
    inc bc
    db $76
    inc d
    db $76
    dec h
    db $76
    ld [hl], $76
    ld b, a
    db $76
    ld e, h
    db $76
    ld [hl], l
    db $76
    sub d
    db $76
    or e
    db $76
    call nc, $e176
    db $76
    ld a, [c]
    db $76
    rra
    ld [hl], a
    ld c, h
    ld [hl], a
    ld e, l
    ld [hl], a
    ld l, [hl]
    ld [hl], a
    ld a, a
    ld [hl], a
    sub b
    ld [hl], a
    and c
    ld [hl], a
    add [hl]
    ld a, b
    sub a
    ld a, b
    xor b
    ld a, b
    cp c
    ld a, b
    jp z, $eb78

jr_01e_703f:
    ld a, b
    inc e
    ld a, c
    dec a
    ld a, c
    ld e, [hl]
    ld a, c
    ld l, a
    ld a, c
    ld a, h
    ld a, c
    adc l
    ld a, c
    sbc d
    ld a, c
    or e
    ld a, c
    ret c

    ld a, c
    push af
    ld a, c
    ld a, [$2b79]
    ld a, d
    inc a
    ld a, d
    ld e, l
    ld a, d
    adc d
    ld a, d
    rst $00
    ld a, d
    ret c

    ld a, d
    ld sp, hl
    ld a, d
    ld a, [hl+]
    ld a, e
    ld l, e
    ld a, e
    add h
    ld a, e
    sbc l
    ld a, e
    or [hl]
    ld a, e
    cp a
    ld a, e
    call nz, $d57b
    ld a, e
    jp c, $fb7b

    ld a, e
    inc e
    ld a, h
    dec a
    ld a, h
    ld b, [hl]
    ld a, h
    ld d, a
    ld a, h
    ld l, b
    ld a, h
    ld [c], a
    ld [hl], a
    inc hl
    ld a, b
    ld d, h
    ld a, b
    ld [hl], l
    ld a, b
    add $73
    ld a, c
    ld a, h
    sub [hl]
    ld a, h
    and a
    ld a, h
    xor h
    ld a, h
    add hl, bc
    nop
    nop
    inc l
    nop
    nop
    ld [$002d], sp
    nop
    db $10
    inc l
    jr nz, @+$0a

    nop
    inc a
    nop
    ld [$3d08], sp
    nop
    ld [$3c10], sp
    jr nz, jr_01e_70be

    nop
    inc l
    ld b, b
    db $10
    ld [$402d], sp
    db $10
    db $10
    inc l
    ld h, b
    stop
    nop
    jr nz, jr_01e_70be

jr_01e_70be:
    nop
    ld [$0021], sp
    nop
    db $10
    ld hl, $0020
    jr jr_01e_70e9

    jr nz, @+$0a

    nop
    jr nc, jr_01e_70ce

jr_01e_70ce:
    ld [$3108], sp
    nop
    ld [$3110], sp
    jr nz, jr_01e_70df

    jr @+$32

    jr nz, @+$12

    nop
    jr nc, jr_01e_711e

    db $10

jr_01e_70df:
    ld [$4031], sp
    db $10
    db $10
    ld sp, $1060
    jr @+$32

jr_01e_70e9:
    ld h, b
    jr jr_01e_70ec

jr_01e_70ec:
    jr nz, jr_01e_712e

    jr @+$0a

    ld hl, $1840
    db $10
    ld hl, $1860
    jr @+$22

    ld h, b
    inc b
    nop
    nop
    ld [bc], a
    nop
    nop
    ld [$2002], sp
    ld [$1200], sp
    nop
    ld [$1208], sp
    jr nz, jr_01e_7110

    nop
    nop
    ld b, $00

jr_01e_7110:
    nop
    ld [$0007], sp
    ld [$1600], sp
    nop
    ld [$1708], sp
    nop
    inc b
    nop

jr_01e_711e:
    nop
    rlca
    jr nz, jr_01e_7122

jr_01e_7122:
    ld [$2006], sp
    ld [$1700], sp
    jr nz, jr_01e_7132

    ld [$2016], sp
    inc c

jr_01e_712e:
    nop
    ld [$0023], sp

jr_01e_7132:
    ld [$3200], sp
    nop
    ld [$3308], sp
    nop
    nop
    db $10
    inc hl
    jr nz, jr_01e_7147

    db $10
    inc sp
    jr nz, jr_01e_714b

    jr @+$34

    jr nz, jr_01e_7157

jr_01e_7147:
    nop
    ld [hl-], a
    ld b, b
    db $10

jr_01e_714b:
    ld [$4033], sp
    jr @+$0a

    inc hl
    ld b, b
    db $10
    db $10
    inc sp
    ld h, b
    db $10

jr_01e_7157:
    jr jr_01e_718b

    ld h, b
    jr @+$12

    inc hl
    ld h, b
    stop
    nop
    jr nz, jr_01e_7163

jr_01e_7163:
    nop
    ld [$0021], sp
    ld [$3000], sp
    nop
    ld [$3108], sp
    nop
    nop
    db $10
    ld hl, $0020
    jr jr_01e_7196

    jr nz, jr_01e_7180

    db $10
    ld sp, $0820
    jr @+$32

    jr nz, jr_01e_7190

jr_01e_7180:
    nop
    jr nc, @+$42

    db $10
    ld [$4031], sp
    jr jr_01e_7189

jr_01e_7189:
    jr nz, @+$42

jr_01e_718b:
    jr @+$0a

    ld hl, $1040

jr_01e_7190:
    db $10
    ld sp, $1060
    jr jr_01e_71c6

jr_01e_7196:
    ld h, b
    jr @+$12

    ld hl, $1860
    jr @+$22

    ld h, b
    stop
    nop
    jr nz, jr_01e_71a4

jr_01e_71a4:
    nop
    ld [$0021], sp
    ld [$3000], sp
    nop
    ld [$3108], sp
    nop
    nop
    jr jr_01e_71d4

    jr nz, jr_01e_71b5

jr_01e_71b5:
    jr nz, @+$22

    jr nz, jr_01e_71c1

    jr jr_01e_71ec

    jr nz, @+$0a

    jr nz, @+$32

    jr nz, @+$1a

jr_01e_71c1:
    nop
    jr nc, jr_01e_7204

    jr jr_01e_71ce

jr_01e_71c6:
    ld sp, $2040
    nop
    jr nz, jr_01e_720c

    jr nz, jr_01e_71d6

jr_01e_71ce:
    ld hl, $1840
    jr jr_01e_7204

    ld h, b

jr_01e_71d4:
    jr jr_01e_71f6

jr_01e_71d6:
    jr nc, jr_01e_7238

    jr nz, jr_01e_71f2

    ld hl, $2060
    jr nz, jr_01e_71ff

    ld h, b
    inc c
    nop
    nop
    inc h
    nop
    nop
    ld [$0025], sp
    ld [$3400], sp

jr_01e_71ec:
    nop
    nop
    jr jr_01e_7215

    jr nz, jr_01e_71f2

jr_01e_71f2:
    jr nz, @+$26

    jr nz, @+$0a

jr_01e_71f6:
    jr nz, jr_01e_722c

    jr nz, jr_01e_7212

    nop
    inc [hl]
    ld b, b
    jr nz, jr_01e_71ff

jr_01e_71ff:
    inc h
    ld b, b
    jr nz, jr_01e_720b

    dec h

jr_01e_7204:
    ld b, b
    jr jr_01e_7227

    inc [hl]
    ld h, b
    jr nz, jr_01e_7223

jr_01e_720b:
    dec h

jr_01e_720c:
    ld h, b
    jr nz, @+$22

    inc h
    ld h, b
    inc c

jr_01e_7212:
    nop
    nop
    inc h

jr_01e_7215:
    nop
    nop
    ld [$0025], sp
    ld [$3400], sp
    nop
    nop
    jr nz, jr_01e_7246

    jr nz, jr_01e_7223

jr_01e_7223:
    jr z, @+$26

    jr nz, @+$0a

jr_01e_7227:
    jr z, @+$36

    jr nz, jr_01e_724b

    nop

jr_01e_722c:
    inc [hl]
    ld b, b
    jr z, jr_01e_7230

jr_01e_7230:
    inc h
    ld b, b
    jr z, jr_01e_723c

    dec h
    ld b, b
    jr nz, jr_01e_7260

jr_01e_7238:
    inc [hl]
    ld h, b
    jr z, jr_01e_725c

jr_01e_723c:
    dec h
    ld h, b
    jr z, jr_01e_7268

    inc h
    ld h, b
    inc b
    nop
    nop
    dec b

jr_01e_7246:
    nop
    nop
    ld [$2005], sp

jr_01e_724b:
    ld [$1500], sp
    nop
    ld [$1508], sp
    jr nz, jr_01e_7258

    nop
    nop
    inc b
    nop

jr_01e_7258:
    nop
    ld [$2004], sp

jr_01e_725c:
    ld [$1400], sp
    nop

jr_01e_7260:
    ld [$1408], sp
    jr nz, jr_01e_726d

    nop
    nop
    inc c

jr_01e_7268:
    nop
    nop
    ld [$000d], sp

jr_01e_726d:
    ld [$1c00], sp
    nop
    ld [$1d08], sp
    nop
    stop
    dec e
    ld h, b
    db $10
    ld [$601c], sp
    jr jr_01e_727f

jr_01e_727f:
    dec c
    ld h, b
    jr @+$0a

    inc c
    ld h, b
    inc b
    jr nz, jr_01e_7288

jr_01e_7288:
    inc c
    nop
    jr nz, jr_01e_7294

    dec c
    nop
    jr z, jr_01e_7290

jr_01e_7290:
    inc e
    nop
    jr z, @+$0a

jr_01e_7294:
    dec e
    nop
    inc b
    jr nc, jr_01e_7299

jr_01e_7299:
    dec e
    ld h, b
    jr nc, jr_01e_72a5

    inc e
    ld h, b
    jr c, jr_01e_72a1

jr_01e_72a1:
    dec c
    ld h, b
    jr c, jr_01e_72ad

jr_01e_72a5:
    inc c
    ld h, b
    ld [$0000], sp
    ld c, $00
    nop

jr_01e_72ad:
    ld [$000f], sp
    ld [$1e00], sp
    nop
    ld [$1f08], sp
    nop
    nop
    db $10
    rrca
    jr nz, jr_01e_72bd

jr_01e_72bd:
    jr jr_01e_72cd

    jr nz, jr_01e_72c9

    db $10
    rra
    jr nz, jr_01e_72cd

    jr @+$20

    jr nz, jr_01e_72d1

jr_01e_72c9:
    nop
    nop
    ld c, $00

jr_01e_72cd:
    nop
    ld [$000f], sp

jr_01e_72d1:
    ld [$1e00], sp
    nop
    ld [$1f08], sp
    nop
    nop
    jr nz, jr_01e_72eb

    jr nz, jr_01e_72de

jr_01e_72de:
    jr z, jr_01e_72ee

    jr nz, jr_01e_72ea

    jr nz, jr_01e_7303

    jr nz, jr_01e_72ee

    jr z, jr_01e_7306

    jr nz, jr_01e_72ed

jr_01e_72ea:
    nop

jr_01e_72eb:
    nop
    scf

jr_01e_72ed:
    nop

jr_01e_72ee:
    ld [$3710], sp
    nop
    nop
    jr nz, @+$39

    nop
    inc b
    nop
    nop
    ld [hl], $00
    nop
    ld [$2036], sp
    ld [$3600], sp
    ld b, b

jr_01e_7303:
    ld [$3608], sp

jr_01e_7306:
    ld h, b
    ld [$1000], sp
    jr z, jr_01e_730c

jr_01e_730c:
    nop
    jr @+$2a

    jr nz, jr_01e_7319

    db $10
    jr c, jr_01e_7314

jr_01e_7314:
    ld [$3818], sp
    jr nz, jr_01e_7319

jr_01e_7319:
    jr nz, @+$38

    nop
    nop
    jr z, jr_01e_7355

    jr nz, jr_01e_7329

    jr nz, @+$38

    ld b, b
    ld [$3628], sp
    ld h, b
    inc c

jr_01e_7329:
    nop
    nop
    jr z, jr_01e_732d

jr_01e_732d:
    nop
    ld [$2028], sp
    ld [$3800], sp
    nop
    ld [$3808], sp
    jr nz, jr_01e_733a

jr_01e_733a:
    db $10
    add hl, hl
    nop
    nop
    jr jr_01e_7369

    jr nz, jr_01e_734a

    db $10
    add hl, sp
    nop
    ld [$3918], sp
    jr nz, jr_01e_734a

jr_01e_734a:
    jr nz, @+$2a

    nop
    nop
    jr z, @+$2a

    jr nz, jr_01e_735a

    jr nz, @+$3a

    nop

jr_01e_7355:
    ld [$3828], sp
    jr nz, jr_01e_7362

jr_01e_735a:
    nop
    nop
    add hl, hl
    nop
    nop
    ld [$2029], sp

jr_01e_7362:
    ld [$3900], sp
    nop
    ld [$3908], sp

jr_01e_7369:
    jr nz, jr_01e_736b

jr_01e_736b:
    jr nz, jr_01e_7396

    nop
    nop
    jr z, jr_01e_739a

    jr nz, jr_01e_737b

    jr nz, @+$3b

    nop
    ld [$3928], sp
    jr nz, @+$06

jr_01e_737b:
    nop
    nop
    ld [$0000], sp
    ld [$0009], sp
    ld [$1800], sp
    nop
    ld [$1908], sp
    nop
    ld bc, $0018
    ld b, l
    ld h, b
    ld [bc], a
    jr jr_01e_739b

    ld b, l
    nop
    db $10

jr_01e_7396:
    ld [$6046], sp
    ld [bc], a

jr_01e_739a:
    db $10

jr_01e_739b:
    db $10
    ld b, l
    ld h, b
    jr jr_01e_73b0

    ld b, [hl]
    nop
    ld [bc], a
    db $10
    jr @+$47

    nop
    ld [$4618], sp
    ld h, b
    ld [bc], a
    ld [$4520], sp
    ld h, b

jr_01e_73b0:
    db $10
    jr nz, @+$48

    nop
    ld [bc], a
    ld [$4528], sp
    nop
    nop
    jr z, @+$48

    ld h, b
    ld [bc], a
    nop
    jr nc, jr_01e_7406

    ld h, b
    ld [$4630], sp
    nop
    inc b
    nop
    nop
    ld b, e
    nop
    nop
    ld [$2043], sp
    ld [$2200], sp
    nop
    ld [$4308], sp
    ld h, b
    ld [bc], a
    nop
    nop
    inc bc
    nop
    nop
    jr nc, jr_01e_73e2

    jr nz, @+$08

    nop

jr_01e_73e2:
    nop
    inc bc
    nop
    nop
    jr nc, @+$05

    jr nz, jr_01e_73f2

    ld [$0003], sp
    ld [$0328], sp
    jr nz, jr_01e_73fa

jr_01e_73f2:
    nop
    inc de
    nop
    ld [$1330], sp
    jr nz, jr_01e_7406

jr_01e_73fa:
    nop
    nop
    inc bc
    nop
    nop
    jr nc, @+$05

    jr nz, jr_01e_740b

    ld [$0003], sp

jr_01e_7406:
    ld [$0328], sp
    jr nz, jr_01e_7413

jr_01e_740b:
    nop
    inc de
    nop
    ld [$1330], sp
    jr nz, jr_01e_7423

jr_01e_7413:
    db $10
    inc bc
    nop
    db $10
    jr nz, @+$05

    jr nz, jr_01e_742b

    ld [$0013], sp
    db $10
    jr z, @+$15

    jr nz, jr_01e_7433

jr_01e_7423:
    nop
    inc bc
    nop
    db $10
    jr nc, jr_01e_742c

    jr nz, jr_01e_743e

jr_01e_742b:
    nop

jr_01e_742c:
    nop
    inc bc
    nop
    ld [$1300], sp
    nop

jr_01e_7433:
    stop
    inc bc
    nop
    jr jr_01e_7439

jr_01e_7439:
    inc de
    nop
    ld [$0308], sp

jr_01e_743e:
    nop
    db $10
    ld [$0013], sp
    jr jr_01e_744d

    inc bc
    nop
    db $10
    db $10
    inc bc
    nop
    jr @+$12

jr_01e_744d:
    inc de
    nop
    jr @+$1a

    inc bc
    nop
    db $10
    jr nz, @+$05

    jr nz, jr_01e_7470

    jr nz, @+$15

    jr nz, jr_01e_7464

    jr z, @+$05

    jr nz, jr_01e_7470

    jr z, @+$15

    jr nz, jr_01e_747c

jr_01e_7464:
    jr z, @+$05

    jr nz, jr_01e_7468

jr_01e_7468:
    jr nc, @+$05

    jr nz, jr_01e_7474

    jr nc, @+$15

    jr nz, jr_01e_7480

jr_01e_7470:
    jr nc, @+$05

    jr nz, jr_01e_748c

jr_01e_7474:
    jr nc, jr_01e_7489

    jr nz, jr_01e_747c

    nop
    nop
    ld a, [bc]
    nop

jr_01e_747c:
    nop
    ld [$000b], sp

jr_01e_7480:
    ld [$1a00], sp
    nop
    ld [$1b08], sp
    nop
    ld [bc], a

jr_01e_7489:
    ld [$0a00], sp

jr_01e_748c:
    nop
    ld [$0b08], sp
    nop
    inc c
    stop
    ld a, [bc]
    nop
    db $10
    ld [$000b], sp
    jr jr_01e_749c

jr_01e_749c:
    ld a, [de]
    nop
    jr @+$0a

    dec de
    nop
    nop
    db $10
    ld a, [bc]
    nop
    nop
    jr @+$0d

    nop
    ld [$1a10], sp
    nop
    ld [$1b18], sp
    nop
    ld [$0a20], sp
    nop
    ld [$0b28], sp
    nop
    db $10
    jr nz, jr_01e_74d7

    nop
    db $10
    jr z, @+$1d

    nop
    inc b
    nop
    db $10
    ld b, h
    nop
    nop
    jr jr_01e_750e

    jr nz, jr_01e_74d4

    db $10
    ld b, h
    ld b, b
    ld [$4418], sp
    ld h, b
    dec b

jr_01e_74d4:
    ld [$4408], sp

jr_01e_74d7:
    nop
    ld [$4410], sp
    jr nz, jr_01e_74ed

    ld [$4044], sp
    db $10
    db $10
    ld b, h
    ld h, b
    nop
    jr @+$49

    nop
    ld b, $10
    nop
    ld b, h
    nop

jr_01e_74ed:
    db $10
    ld [$2044], sp
    jr jr_01e_74f3

jr_01e_74f3:
    ld b, h
    ld b, b
    jr @+$0a

    ld b, h
    ld h, b
    ld [$4710], sp
    nop
    ld [bc], a
    ld d, $47
    nop
    inc b
    jr jr_01e_7504

jr_01e_7504:
    ld b, a
    nop
    ld [de], a
    ld b, $47
    nop
    inc c
    inc c
    ld b, a
    nop

jr_01e_750e:
    ld b, $12
    ld b, a
    nop
    inc b
    nop
    nop
    ld b, h
    nop
    nop
    ld [$2044], sp
    ld [$4400], sp
    ld b, b
    ld [$4408], sp
    ld h, b
    ld [bc], a
    ld b, $02
    ld b, a
    nop
    nop
    ld [$0047], sp
    ld bc, $00a0
    ld c, l
    nop
    ld [$0000], sp
    ld h, $00
    nop
    ld [$0027], sp
    ld [$3600], sp
    nop
    ld [$3708], sp
    nop
    stop
    jr z, jr_01e_7546

jr_01e_7546:
    db $10
    ld [$0029], sp
    jr jr_01e_754c

jr_01e_754c:
    jr c, jr_01e_754e

jr_01e_754e:
    jr jr_01e_7558

    add hl, sp
    nop
    ld [$0000], sp
    daa
    jr nz, jr_01e_7558

jr_01e_7558:
    ld [$2026], sp
    ld [$3700], sp
    jr nz, jr_01e_7568

    ld [$2036], sp
    stop
    add hl, hl
    jr nz, jr_01e_7578

jr_01e_7568:
    ld [$2028], sp
    jr jr_01e_756d

jr_01e_756d:
    add hl, sp
    jr nz, jr_01e_7588

    ld [$2038], sp
    inc b
    nop
    nop
    inc c
    nop

jr_01e_7578:
    nop
    ld [$000d], sp
    ld [$0c00], sp
    ld b, b
    ld [$0d08], sp
    ld b, b
    inc b
    nop
    nop
    ld b, h

jr_01e_7588:
    nop
    nop
    ld [$2044], sp
    ld [$4400], sp
    ld b, b
    ld [$4408], sp
    ld h, b
    ld bc, $0000
    ld b, l
    nop
    rlca
    nop
    nop
    ld c, l
    nop
    nop
    ld [$002f], sp
    nop
    db $10
    ld c, l
    jr nz, @+$0a

    nop
    ld c, [hl]
    nop
    ld [$0708], sp
    nop
    ld [$4e10], sp
    jr nz, jr_01e_75c4

    ld [$003f], sp
    rlca
    nop
    ld [$403f], sp
    ld [$4e00], sp
    ld b, b
    ld [$0708], sp
    ld b, b

jr_01e_75c4:
    ld [$4e10], sp
    ld h, b
    stop
    ld c, l
    ld b, b
    db $10
    ld [$402f], sp
    db $10
    db $10
    ld c, l
    ld h, b
    ld bc, $00a0
    nop
    db $10
    ld b, $00
    nop
    ld a, [hl+]
    nop
    nop
    ld [$002b], sp
    ld [$3a00], sp
    nop
    stop
    ld a, [hl-]
    ld b, b
    jr jr_01e_75ec

jr_01e_75ec:
    ld a, [hl+]
    ld b, b
    jr jr_01e_75f8

    dec hl
    ld b, b
    inc b
    nop
    nop
    nop
    nop
    nop

jr_01e_75f8:
    ld [$0001], sp
    ld [$1000], sp
    nop
    ld [$1108], sp
    nop
    inc b
    nop
    nop
    ld bc, $00a0
    ld [$a000], sp
    ld [$1100], sp
    and b
    ld [$1008], sp
    and b
    inc b
    nop
    nop
    ld a, [bc]
    nop
    nop
    ld [$000b], sp
    ld [$1a00], sp
    nop
    ld [$1b08], sp
    nop
    inc b
    nop
    nop
    dec bc
    jr nz, jr_01e_762b

jr_01e_762b:
    ld [$200a], sp
    ld [$1b00], sp
    jr nz, jr_01e_763b

    ld [$201a], sp
    inc b
    jr nz, jr_01e_7639

jr_01e_7639:
    dec b
    nop

jr_01e_763b:
    jr nz, jr_01e_7645

    dec b
    jr nz, jr_01e_7668

    nop
    dec d
    nop
    jr z, @+$0a

jr_01e_7645:
    dec d
    jr nz, @+$07

    jr jr_01e_764a

jr_01e_764a:
    inc b
    nop
    jr jr_01e_7656

    inc b
    jr nz, jr_01e_7671

    nop
    inc d
    nop
    jr nz, jr_01e_765e

jr_01e_7656:
    inc d
    jr nz, jr_01e_7681

    inc b
    ld b, c
    nop
    ld b, $10

jr_01e_765e:
    nop
    dec b
    nop
    db $10
    ld [$2005], sp
    jr jr_01e_7667

jr_01e_7667:
    dec d

jr_01e_7668:
    nop
    jr jr_01e_7673

    dec d
    jr nz, jr_01e_768e

    inc b
    ld b, d
    nop

jr_01e_7671:
    jr z, @+$06

jr_01e_7673:
    ld b, d
    nop
    rlca
    ld [$0400], sp
    nop
    ld [$0408], sp
    jr nz, @+$12

    nop
    inc d

jr_01e_7681:
    nop
    db $10
    ld [$2014], sp
    jr jr_01e_768c

    ld b, c
    nop
    jr nz, jr_01e_7690

jr_01e_768c:
    ld b, c
    nop

jr_01e_768e:
    jr z, @+$06

jr_01e_7690:
    ld b, c
    nop
    ld [$0000], sp
    dec b
    nop
    nop
    ld [$2005], sp
    ld [$1500], sp
    nop
    ld [$1508], sp
    jr nz, @+$12

    inc b
    ld b, d
    nop
    jr jr_01e_76ad

    ld b, d
    nop
    jr nz, jr_01e_76b1

jr_01e_76ad:
    ld b, d
    nop
    jr z, @+$06

jr_01e_76b1:
    ld b, d
    nop
    ld [$0000], sp
    inc b
    nop
    nop
    ld [$2004], sp
    ld [$1400], sp
    nop
    ld [$1408], sp
    jr nz, jr_01e_76d5

    inc b
    ld b, c
    nop
    jr jr_01e_76ce

    ld b, c
    nop
    jr nz, jr_01e_76d2

jr_01e_76ce:
    ld b, c
    nop
    jr z, jr_01e_76d6

jr_01e_76d2:
    ld b, c
    nop
    inc bc

jr_01e_76d5:
    nop

jr_01e_76d6:
    nop
    dec a
    nop
    nop
    ld [$003d], sp
    ld [$3d08], sp
    nop
    inc b
    nop
    nop
    ld b, $00
    nop
    ld [$2006], sp
    ld [$1600], sp
    nop
    ld [$1708], sp
    nop
    dec bc
    nop
    db $10
    ld b, d
    nop
    ld [$4200], sp
    nop
    ld [$4208], sp
    nop
    ld [$4210], sp
    nop
    ld [$4218], sp
    nop
    ld [$4220], sp
    nop
    db $10
    db $10
    ld b, d
    nop
    jr jr_01e_7719

    ld b, d
    nop
    jr @+$1a

    ld b, d
    nop
    jr nz, jr_01e_7719

jr_01e_7719:
    ld b, d
    nop
    jr nz, @+$22

    ld b, d
    nop
    dec bc
    nop
    db $10
    ld b, c
    nop
    ld [$4100], sp
    nop
    ld [$4108], sp
    nop
    ld [$4110], sp
    nop
    ld [$4118], sp
    nop
    ld [$4120], sp
    nop
    db $10
    db $10
    ld b, c
    nop
    jr jr_01e_7746

    ld b, c
    nop
    jr @+$1a

    ld b, c
    nop
    jr nz, jr_01e_7746

jr_01e_7746:
    ld b, c
    nop
    jr nz, jr_01e_776a

    ld b, c
    nop
    inc b
    nop
    nop
    ld c, c
    nop
    nop
    jr z, jr_01e_779d

    nop
    jr z, jr_01e_7757

jr_01e_7757:
    ld c, c
    nop
    jr z, jr_01e_7783

Call_01e_775b:
    ld c, c
    nop
    inc b
    nop
    nop
    ld c, c
    nop
    nop
    jr @+$4b

    nop
    jr jr_01e_7768

jr_01e_7768:
    ld c, c
    nop

jr_01e_776a:
    jr jr_01e_7784

    ld c, c
    nop
    inc b
    nop
    nop
    ld c, c
    nop
    nop
    ld [$0049], sp
    ld [$4900], sp
    nop
    ld [$4908], sp
    nop
    inc b
    nop
    nop
    ld b, e

jr_01e_7783:
    nop

jr_01e_7784:
    nop
    ld [$2043], sp
    ld [$4300], sp
    ld b, b
    ld [$4308], sp
    ld h, b
    inc b
    ld [$3308], sp
    nop
    ld [$3310], sp
    jr nz, jr_01e_77aa

    ld [$4033], sp

jr_01e_779d:
    db $10
    db $10
    inc sp
    ld h, b
    stop
    nop
    ld [hl+], a
    nop
    nop
    ld [$0023], sp

jr_01e_77aa:
    nop
    db $10
    inc hl
    jr nz, jr_01e_77af

jr_01e_77af:
    jr @+$24

    jr nz, @+$0a

    nop
    ld [hl-], a
    nop
    ld [$4308], sp
    nop
    ld [$4310], sp
    jr nz, jr_01e_77c7

    jr @+$34

    jr nz, @+$12

    nop
    ld [hl-], a
    ld b, b
    db $10

jr_01e_77c7:
    ld [$4043], sp
    db $10
    db $10
    ld b, e
    ld h, b
    db $10
    jr @+$34

    ld h, b
    jr jr_01e_77d4

jr_01e_77d4:
    ld [hl+], a
    ld b, b
    jr jr_01e_77e0

    inc hl
    ld b, b
    jr jr_01e_77ec

    inc hl
    ld h, b
    jr @+$1a

jr_01e_77e0:
    ld [hl+], a
    ld h, b
    stop
    nop
    ld [hl+], a
    nop
    nop
    ld [$003b], sp
    nop

jr_01e_77ec:
    db $10
    inc hl
    jr nz, jr_01e_77f0

jr_01e_77f0:
    jr @+$24

    jr nz, @+$0a

    nop
    ld [hl-], a
    nop
    ld [$4308], sp
    nop
    ld [$4310], sp
    jr nz, jr_01e_7808

    jr @+$34

    jr nz, @+$12

    nop
    ld [hl-], a
    ld b, b
    db $10

jr_01e_7808:
    ld [$4043], sp
    db $10
    db $10
    ld b, e
    ld h, b
    db $10
    jr jr_01e_7844

    ld h, b
    jr jr_01e_7815

jr_01e_7815:
    ld [hl+], a
    ld b, b
    jr jr_01e_7821

    inc hl
    ld b, b
    jr jr_01e_782d

    inc hl
    ld h, b
    jr @+$1a

jr_01e_7821:
    ld [hl+], a
    ld h, b
    inc c
    nop
    nop
    ld [hl-], a
    nop
    nop
    ld [$0043], sp
    nop

jr_01e_782d:
    db $10
    ld b, e
    jr nz, jr_01e_7831

jr_01e_7831:
    jr jr_01e_7865

    jr nz, @+$0a

    nop
    ld [hl-], a
    ld b, b
    ld [$4308], sp
    ld b, b
    ld [$4310], sp
    ld h, b
    ld [$3218], sp
    ld h, b

jr_01e_7844:
    stop
    ld [hl+], a
    ld b, b
    db $10
    ld [$4023], sp
    db $10
    db $10
    inc hl
    ld h, b
    db $10
    jr jr_01e_7875

    ld h, b
    ld [$0000], sp
    ld [hl-], a
    ld b, b
    nop
    ld [$4043], sp
    nop
    db $10
    ld b, e
    ld h, b
    nop
    jr jr_01e_7896

    ld h, b

jr_01e_7865:
    ld [$2200], sp
    ld b, b
    ld [$2308], sp
    ld b, b
    ld [$2310], sp
    ld h, b
    ld [$2218], sp
    ld h, b

jr_01e_7875:
    inc b
    nop
    nop
    ld [hl+], a
    ld b, b
    nop
    ld [$4023], sp
    nop
    db $10
    inc hl
    ld h, b
    nop
    jr jr_01e_78a7

    ld h, b
    inc b
    ld [$4c18], sp
    jr nz, @+$22

    ld [$004b], sp
    jr nc, jr_01e_78b1

    ld c, h
    nop
    jr jr_01e_78c5

    ld c, e

jr_01e_7896:
    ld b, b
    inc b
    nop
    jr jr_01e_78e7

    nop
    jr nz, jr_01e_789e

jr_01e_789e:
    ld c, e
    ld b, b
    jr c, jr_01e_78c2

    ld c, h
    jr nz, jr_01e_78bd

    jr c, jr_01e_78f2

jr_01e_78a7:
    nop
    inc b
    db $10
    ld [$404a], sp
    jr nc, jr_01e_78bf

    ld c, d
    nop

jr_01e_78b1:
    jr z, @+$32

    ld c, d
    jr nz, @+$0a

    jr z, @+$4c

    ld h, b
    inc b
    ld [$4a00], sp

jr_01e_78bd:
    jr nz, jr_01e_78f7

jr_01e_78bf:
    ld [$604a], sp

jr_01e_78c2:
    jr nc, jr_01e_78fc

    ld c, d

jr_01e_78c5:
    ld b, b
    nop
    jr nc, jr_01e_7913

    nop
    ld [$3000], sp
    ld b, h
    nop
    nop
    jr c, jr_01e_7916

    jr nz, @+$0a

    jr nc, @+$46

    ld b, b
    ld [$4438], sp
    ld h, b
    ld h, $0a
    ld b, h
    nop
    ld h, $12
    ld b, h
    jr nz, @+$30

    ld a, [bc]
    ld b, h
    ld b, b

jr_01e_78e7:
    ld l, $12
    ld b, h
    ld h, b
    inc c
    ld c, $22
    ld b, h
    nop
    ld c, $2a

jr_01e_78f2:
    ld b, h
    jr nz, jr_01e_790b

    ld [hl+], a
    ld b, h

jr_01e_78f7:
    ld b, b
    ld d, $2a
    ld b, h
    ld h, b

jr_01e_78fc:
    ld b, $32
    ld b, a
    nop
    nop
    jr c, jr_01e_794a

    nop
    ld a, [de]
    ld d, $44
    nop
    ld a, [de]
    ld e, $44

jr_01e_790b:
    jr nz, jr_01e_792f

    ld d, $44
    ld b, b
    ld [hl+], a
    ld e, $44

jr_01e_7913:
    ld h, b
    jr nc, @+$0a

jr_01e_7916:
    ld b, a
    nop
    ld a, [hl+]
    ld c, $47
    nop
    ld [$3206], sp
    ld b, a
    nop
    nop
    jr c, jr_01e_796b

    nop
    ld [de], a
    ld h, $47
    nop
    inc c
    inc l
    ld b, a
    nop
    ld e, $1a

jr_01e_792f:
    ld b, a
    nop
    jr @+$22

    ld b, a
    nop
    ld a, [hl+]
    ld c, $47
    nop
    inc h
    inc d
    ld b, a
    nop
    ld [$0000], sp
    dec [hl]
    jr nz, @+$0a

    nop
    dec [hl]
    ld b, b
    stop
    dec [hl]
    nop

jr_01e_794a:
    jr jr_01e_794c

jr_01e_794c:
    dec [hl]
    ld h, b
    nop
    ld b, b
    dec [hl]
    nop
    ld [$3540], sp
    ld h, b
    db $10
    ld b, b
    dec [hl]
    jr nz, jr_01e_7973

    ld b, b
    dec [hl]
    ld b, b
    inc b
    nop
    nop
    ld a, [hl+]
    nop
    nop
    ld [$002b], sp
    ld [$3a00], sp
    nop

jr_01e_796b:
    ld [$3b08], sp
    nop
    inc bc
    nop
    nop
    ccf

jr_01e_7973:
    nop
    nop
    ld [$003f], sp
    ld [$3f06], sp
    nop
    inc b
    nop
    nop
    ld c, $00
    nop
    ld [$200e], sp
    ld [$0f00], sp
    nop
    ld [$0f08], sp
    jr nz, jr_01e_7991

    stop
    inc l

jr_01e_7991:
    nop
    db $10
    ld [$003c], sp
    db $10
    db $10
    dec l
    nop
    ld b, $10
    db $10
    ld sp, $1000
    jr jr_01e_79d3

    nop
    ld [$2c10], sp
    nop
    ld [$3c18], sp
    nop
    ld [$2d20], sp
    nop
    db $10
    jr nz, @+$2f

    nop
    add hl, bc
    ld [$3120], sp
    nop
    db $10
    jr nz, jr_01e_79ec

    nop
    ld [$3128], sp
    nop
    db $10
    jr z, jr_01e_79f4

    nop
    nop
    jr nz, jr_01e_79f3

    nop
    nop
    jr z, jr_01e_7a07

    nop
    nop
    jr nc, jr_01e_79fc

    nop
    ld [$2d30], sp

jr_01e_79d3:
    nop
    db $10
    jr nc, @+$2f

    nop
    rlca
    nop
    nop
    ld b, [hl]
    nop
    ld [$4702], sp
    nop
    db $10
    inc bc
    ld c, b
    nop
    jr jr_01e_79eb

    ld c, b
    nop
    jr nz, jr_01e_79f0

jr_01e_79eb:
    ld c, b

jr_01e_79ec:
    nop
    jr z, jr_01e_79f4

    ld c, b

jr_01e_79f0:
    nop
    jr nc, jr_01e_79f8

jr_01e_79f3:
    ld c, b

jr_01e_79f4:
    nop
    ld bc, $0000

jr_01e_79f8:
    ld b, d
    nop
    inc c
    nop

jr_01e_79fc:
    nop
    inc h
    nop
    nop
    ld [$0025], sp
    ld [$3400], sp
    nop

jr_01e_7a07:
    nop
    db $10
    dec h
    jr nz, jr_01e_7a0c

jr_01e_7a0c:
    jr @+$26

    jr nz, @+$0a

    jr @+$36

    jr nz, @+$12

    nop
    inc [hl]
    ld b, b
    jr jr_01e_7a19

jr_01e_7a19:
    inc h
    ld b, b
    jr jr_01e_7a25

    dec h
    ld b, b
    db $10
    jr jr_01e_7a56

    ld h, b
    jr @+$12

jr_01e_7a25:
    dec h
    ld h, b
    jr jr_01e_7a41

    inc h
    ld h, b
    inc b
    nop
    nop
    ld b, e
    nop
    nop
    ld [$2043], sp
    ld [$4300], sp
    ld b, b
    ld [$4308], sp
    ld h, b
    ld [$0000], sp
    ld c, c
    nop

jr_01e_7a41:
    ld [bc], a
    ld [$0049], sp
    jr jr_01e_7a47

jr_01e_7a47:
    ld c, c
    nop
    db $10
    db $10
    ld c, c
    nop
    ld [$4300], sp
    nop
    ld [$4308], sp
    jr nz, jr_01e_7a66

jr_01e_7a56:
    nop
    ld b, e
    ld b, b
    db $10
    ld [$6043], sp
    dec bc
    nop
    nop
    ld c, c
    nop
    jr jr_01e_7a66

    ld c, c
    nop

jr_01e_7a66:
    inc d
    db $10
    ld c, c
    nop
    ld [$4300], sp
    nop
    nop
    ld [$2043], sp
    stop
    ld b, e
    ld b, b
    db $10
    ld [$6043], sp
    inc b
    ld [$0043], sp
    inc b
    db $10
    ld b, e
    jr nz, jr_01e_7a8f

    ld [$4043], sp
    inc c
    db $10
    ld b, e
    ld h, b
    rrca
    nop
    ld [$0049], sp

jr_01e_7a8f:
    ld [$4910], sp
    nop
    jr nz, jr_01e_7a95

jr_01e_7a95:
    ld c, c
    nop
    ld [$4300], sp
    nop
    ld [$4308], sp
    jr nz, jr_01e_7ab0

    nop
    ld b, e
    ld b, b
    db $10
    ld [$6043], sp
    db $10
    db $10
    ld b, e
    nop
    db $10
    jr jr_01e_7af1

    jr nz, jr_01e_7ac8

jr_01e_7ab0:
    db $10
    ld b, e
    ld b, b
    jr jr_01e_7acd

    ld b, e
    ld h, b
    jr nz, @+$0a

    ld b, e
    nop
    jr nz, jr_01e_7acd

    ld b, e
    jr nz, jr_01e_7ae8

    ld [$4043], sp
    jr z, jr_01e_7ad5

    ld b, e
    ld h, b
    inc b

jr_01e_7ac8:
    nop
    nop
    ld c, c
    nop
    nop

jr_01e_7acd:
    db $10
    ld c, c
    nop
    nop
    jr nz, jr_01e_7b1c

    nop
    nop

jr_01e_7ad5:
    jr nc, jr_01e_7b20

    nop
    ld [$0000], sp
    ld c, c
    nop
    nop
    db $10
    ld c, c
    nop
    nop
    jr nz, jr_01e_7b2d

    nop
    nop
    jr nc, jr_01e_7b31

jr_01e_7ae8:
    nop
    ld [$4908], sp
    nop
    ld [$4918], sp
    nop

jr_01e_7af1:
    ld [$4928], sp
    nop
    ld [$4938], sp
    nop
    inc c
    nop
    nop
    ld c, c
    nop
    nop
    db $10
    ld c, c
    nop
    nop
    jr nz, jr_01e_7b4e

    nop
    nop
    jr nc, jr_01e_7b52

    nop
    ld [$4908], sp
    nop
    ld [$4918], sp
    nop
    ld [$4928], sp
    nop
    ld [$4938], sp
    nop
    stop

jr_01e_7b1c:
    ld c, c
    nop
    db $10
    db $10

jr_01e_7b20:
    ld c, c
    nop
    db $10
    jr nz, jr_01e_7b6e

    nop
    db $10
    jr nc, @+$4b

    nop
    rrca
    nop
    nop

jr_01e_7b2d:
    ld c, c
    nop
    nop
    db $10

jr_01e_7b31:
    ld c, c
    nop
    nop
    jr nz, jr_01e_7b7f

    nop
    nop
    jr nc, jr_01e_7b83

    nop
    ld [$4908], sp
    nop
    ld [$4918], sp
    nop
    ld [$4928], sp
    nop
    ld [$4938], sp
    nop
    stop
    ld c, c

jr_01e_7b4e:
    nop
    db $10
    db $10
    ld c, c

jr_01e_7b52:
    nop
    db $10
    jr nz, jr_01e_7b9f

    nop
    db $10
    jr nc, jr_01e_7ba3

    nop
    jr jr_01e_7b65

    ld c, c
    nop
    jr @+$1a

    ld c, c
    nop
    jr jr_01e_7b8d

jr_01e_7b65:
    ld c, c
    nop
    jr jr_01e_7ba1

    ld c, c
    nop
    ld b, $10
    nop

jr_01e_7b6e:
    ld h, $00
    db $10
    ld [$0027], sp
    ld [$2610], sp
    nop
    ld [$2718], sp
    nop
    nop
    jr nz, @+$28

jr_01e_7b7f:
    nop
    nop
    jr z, jr_01e_7baa

jr_01e_7b83:
    nop
    ld b, $18
    nop
    daa
    nop
    db $10
    ld [$0026], sp

jr_01e_7b8d:
    db $10
    db $10
    daa
    nop
    ld [$2618], sp
    nop
    ld [$2720], sp
    nop
    nop
    jr z, jr_01e_7bc2

    nop
    ld b, $00

jr_01e_7b9f:
    nop
    inc e

jr_01e_7ba1:
    nop
    nop

jr_01e_7ba3:
    ld [$001d], sp
    stop
    inc e
    nop

jr_01e_7baa:
    db $10
    ld [$001d], sp
    jr nz, jr_01e_7bb0

jr_01e_7bb0:
    inc e
    nop
    jr nz, @+$0a

    dec e
    nop
    ld [bc], a
    nop
    nop
    inc bc
    nop
    ld [$1300], sp
    nop
    ld bc, $0000

jr_01e_7bc2:
    inc bc
    nop
    inc b
    nop
    nop
    inc bc
    nop
    nop
    ld [$2003], sp
    ld [$1300], sp
    nop
    ld [$1308], sp
    jr nz, jr_01e_7bd7

    nop

jr_01e_7bd7:
    nop
    ld b, $00
    ld [$0000], sp
    ld l, $00
    nop
    jr nc, jr_01e_7c10

    jr nz, jr_01e_7c14

    nop
    ld l, $40
    jr nc, jr_01e_7c19

    ld l, $60
    nop
    jr jr_01e_7c1d

    nop
    jr nc, @+$1a

    cpl
    ld b, b
    jr jr_01e_7bf5

jr_01e_7bf5:
    ld a, $00
    jr jr_01e_7c29

    ld a, $20
    ld [$0000], sp
    ld l, $00
    nop
    jr nz, jr_01e_7c31

    jr nz, jr_01e_7c25

    nop
    ld l, $40
    jr nz, jr_01e_7c2a

    ld l, $60
    nop
    db $10
    cpl
    nop

jr_01e_7c10:
    jr nz, jr_01e_7c22

    cpl
    ld b, b

jr_01e_7c14:
    stop
    ld a, $00
    db $10

jr_01e_7c19:
    jr nz, jr_01e_7c59

    jr nz, jr_01e_7c25

jr_01e_7c1d:
    nop
    nop
    ld l, $00
    nop

jr_01e_7c22:
    db $10
    ld l, $20

jr_01e_7c25:
    stop
    ld l, $40

jr_01e_7c29:
    db $10

jr_01e_7c2a:
    db $10
    ld l, $60
    nop
    ld [$002f], sp

jr_01e_7c31:
    db $10
    ld [$402f], sp
    ld [$3e00], sp
    nop
    ld [$3e10], sp
    jr nz, jr_01e_7c40

    nop
    nop

jr_01e_7c40:
    ld e, $00
    nop
    ld [$001f], sp
    inc b
    nop
    nop
    ld c, b
    nop
    nop
    ld [$2048], sp
    ld [$1200], sp
    nop

jr_01e_7c53:
    ld [$1208], sp
    jr nz, jr_01e_7c5c

    nop

jr_01e_7c59:
    nop
    ld c, d
    nop

jr_01e_7c5c:
    nop
    ld [$0007], sp
    ld [$1600], sp

jr_01e_7c63:
    nop
    ld [$1708], sp
    nop
    inc b

jr_01e_7c69:
    nop
    nop
    rlca
    jr nz, jr_01e_7c6e

jr_01e_7c6e:
    ld [$204a], sp
    ld [$1700], sp
    jr nz, jr_01e_7c7e

    ld [$2016], sp
    rlca
    nop
    db $10
    cpl
    nop

jr_01e_7c7e:
    ld bc, $2f08

jr_01e_7c81:
    nop
    ld bc, $2f18
    nop
    ld [bc], a
    nop
    ld l, $00
    ld [bc], a
    jr nz, jr_01e_7cbb

    jr nz, jr_01e_7c99

    nop
    ld a, $00
    ld a, [bc]
    jr nz, jr_01e_7cd3

    jr nz, jr_01e_7c9b

    nop
    ld [bc], a

jr_01e_7c99:
    ld c, e
    nop

jr_01e_7c9b:
    nop
    ld a, [bc]
    ld c, h
    nop
    ld [$4c00], sp
    ld h, b
    ld [$4b08], sp
    ld h, b
    ld bc, $0000
    ld c, l
    nop
    ld bc, $0000
    ld c, [hl]
    nop
    db $10
    ld l, b
    db $10
    ld [hl], b
    db $10
    ld a, b
    db $10
    add b
    db $10
    adc b

jr_01e_7cbb:
    db $10
    sub b
    db $10
    sbc b
    jr jr_01e_7d29

    jr jr_01e_7d33

    jr @+$7a

    inc [hl]
    jr z, @+$1a

    add b
    jr jr_01e_7c53

    jr @-$66

    jr nz, jr_01e_7d37

    jr nz, jr_01e_7d41

    jr nz, jr_01e_7d4b

jr_01e_7cd3:
    jr nz, @-$7e

    jr nz, @-$76

    jr nz, jr_01e_7c69

    jr nz, @-$66

    jr z, jr_01e_7d45

    jr z, jr_01e_7d4f

    jr z, jr_01e_7d59

    jr z, jr_01e_7c63

    jr z, @-$76

    jr nc, jr_01e_7d4f

    jr nc, jr_01e_7d59

    jr nc, jr_01e_7d63

    jr nc, @-$7e

    jr nc, @-$6e

    jr nc, @-$66

    jr c, jr_01e_7d5b

    jr c, jr_01e_7d6d

    jr c, @-$7e

    jr c, jr_01e_7c81

    ld b, b
    ld l, b
    ld b, b
    ld [hl], b
    ld b, b
    ld a, b
    ld b, b
    add b
    ld b, b
    adc b
    ld b, b
    sbc b
    db $10
    ld h, b
    jr jr_01e_7d69

    jr nz, jr_01e_7d6b

    jr z, jr_01e_7d6d

    jr nc, jr_01e_7d6f

    ld b, b
    ld h, b
    ld e, b
    jr z, jr_01e_7d57

    jr c, jr_01e_7d49

    ld c, b
    jr nz, jr_01e_7d71

    ld [hl-], a
    ld a, b
    ld e, b
    ld e, b
    inc l
    ld l, h
    inc [hl]
    add b
    ld c, b
    ld [hl], b
    ld b, d
    ld [hl], $38
    ld b, h
    ld b, b
    ld d, d

jr_01e_7d29:
    ld c, b
    ld h, b
    ld a, $6e
    jr z, jr_01e_7dab

    jr z, jr_01e_7cbb

    ld d, b
    inc a

jr_01e_7d33:
    ld c, b
    ld d, b
    ld b, b
    ld h, h

jr_01e_7d37:
    jr c, jr_01e_7d71

    ld d, b
    jr nc, jr_01e_7d8c

    jr c, @+$52

    ld b, b
    ld d, b
    ld c, b

jr_01e_7d41:
    ld d, b
    ld d, b
    ld c, b
    ld e, b

jr_01e_7d45:
    ld d, b
    ld b, h
    ld c, b
    ld c, b

jr_01e_7d49:
    ld c, b
    ld c, h

jr_01e_7d4b:
    ld b, b
    ld d, b
    ld b, b
    ld d, h

jr_01e_7d4f:
    jr c, jr_01e_7da9

    jr c, jr_01e_7daf

    jr nc, jr_01e_7db9

    ld c, b
    ld b, b

jr_01e_7d57:
    ld c, b
    add hl, sp

jr_01e_7d59:
    inc h
    adc b

jr_01e_7d5b:
    inc h
    ld [hl], b
    inc e
    ld [hl], b
    inc e
    adc b
    inc [hl]
    ld l, b

jr_01e_7d63:
    inc [hl]
    adc b
    ld l, b
    ld d, b
    ld h, b
    ld d, b

jr_01e_7d69:
    ld l, b
    ld h, b

jr_01e_7d6b:
    ld e, b
    ld d, b

jr_01e_7d6d:
    ld h, b
    ld h, b

jr_01e_7d6f:
    ld l, b
    ld b, b

jr_01e_7d71:
    ld b, b
    ld b, b
    jr c, @+$42

    dec bc
    ld h, b
    ld b, h
    ld c, b
    ld b, b
    inc d
    ld c, b
    inc e
    ld d, b
    inc h
    ld c, h
    inc h
    db $10
    ld h, d
    ld [de], a
    ld h, d
    ld [de], a
    ld h, b
    jr nz, jr_01e_7dfb

    ld [hl+], a
    ld [hl], d
    ld [hl+], a

jr_01e_7d8c:
    ld [hl], b
    jr z, jr_01e_7df1

    ld d, b
    ld a, [bc]
    ld d, d
    ld a, [bc]
    jr c, jr_01e_7dc5

    ld b, b
    ld c, b
    jr nc, jr_01e_7de1

    ld b, b
    jr nc, @+$32

    ld b, b
    jr c, jr_01e_7de7

    ld b, b
    ld c, d
    ld c, b
    ld c, e
    ld d, b
    ld c, h
    ld e, b
    ld c, l
    ld h, b
    ld c, l

jr_01e_7da9:
    ld l, b
    ld c, l

jr_01e_7dab:
    jr c, jr_01e_7dbd

    ld d, b
    db $10

jr_01e_7daf:
    jr c, @+$2a

    ld c, b
    jr @+$42

    jr nz, jr_01e_7dfe

    jr nz, jr_01e_7df8

    inc a

jr_01e_7db9:
    jr c, jr_01e_7e0b

    jr z, jr_01e_7e21

jr_01e_7dbd:
    inc e
    sub b
    inc h
    add b
    inc l
    ld [hl], b
    jr nc, jr_01e_7dfd

jr_01e_7dc5:
    db $10
    ld d, b
    inc a
    ld b, b
    ld b, b
    ld e, b
    jr nc, @+$5a

    ld e, b
    ld c, b
    ld d, b
    ld e, b
    ld c, b
    ld l, b
    ld b, b
    jr jr_01e_7dfe

    ld e, b
    ld b, b
    jr c, @+$4a

    jr c, @+$0a

    ld [hl], b
    ld b, h
    inc e
    inc a
    ld e, b

jr_01e_7de1:
    jr c, @+$62

    ld [$3860], sp
    ld [hl], b

jr_01e_7de7:
    jr c, @+$6e

    jr c, @+$66

    inc e
    ld [hl], h
    ld l, $74
    inc [hl]
    ld d, b

jr_01e_7df1:
    cpl
    ld h, b
    ld sp, $4c70
    jr nc, @+$3d

jr_01e_7df8:
    ld b, b
    dec l
    ld d, b

jr_01e_7dfb:
    ld h, $60

jr_01e_7dfd:
    dec l

jr_01e_7dfe:
    ld [hl], b
    jr z, @+$52

    ld e, $60
    add hl, hl
    ld [hl], b
    ld d, $60
    inc d
    ld e, b
    ld [de], a
    ld d, h

jr_01e_7e0b:
    inc d
    ld d, b
    jr @+$4e

    inc e
    ld c, b
    ld c, b
    jr z, jr_01e_7e14

jr_01e_7e14:
    nop
    push hl
    push de
    push bc
    ld a, [$cf78]
    push af
    ld a, [$d092]
    push af
    xor a

jr_01e_7e21:
    ld [$d060], a
    ld [$c02a], a
    dec a
    ld [$c0ee], a
    call Call_000_0e45
    ld a, $01
    ldh [$ba], a
    ld a, $8c
    call Call_000_0e45
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ldh [$d7], a
    ld a, [$cee4]
    ld [$cf17], a
    ld c, $00
    call Call_01e_7ee0
    ld a, [$cee5]
    ld [$cf78], a
    ld [$d092], a
    call Call_01e_7ee5
    ld de, $9000
    ld hl, $9310
    ld bc, $0031
    call Call_000_02dd
    ld a, [$cee4]
    ld [$cf78], a
    ld [$d092], a
    call Call_01e_7ee5
    ld a, $01
    ldh [$ba], a
    ld a, [$cee4]
    call Call_000_2dc7
    call Call_000_3790
    ld c, $02
    ld a, $e5
    call Call_000_0e35
    ld c, $50
    call Call_000_3781
    ld c, $01
    call Call_01e_7ee0
    ld bc, $0110

jr_01e_7e8f:
    push bc
    call Call_01e_7f26
    jr c, jr_01e_7ed5

    call Call_01e_7eee
    pop bc
    inc b
    dec c
    dec c
    jr nz, jr_01e_7e8f

    xor a
    ld [$cee7], a
    ld a, $31
    ld [$cee6], a
    call Call_01e_7f02
    ld a, [$cee5]

jr_01e_7ead:
    ld [$cf17], a
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld a, [$cf17]
    call Call_000_2dc7
    ld c, $00
    call Call_01e_7ee0
    pop af
    ld [$d092], a
    pop af
    ld [$cf78], a
    pop bc
    pop de
    pop hl
    ld a, [$cee7]
    and a
    ret z

    scf
    ret


jr_01e_7ed5:
    pop bc
    ld a, $01
    ld [$cee7], a
    ld a, [$cee4]
    jr jr_01e_7ead

Call_01e_7ee0:
    ld b, $0b
    jp Jump_000_3e1f


Call_01e_7ee5:
    call Call_000_2f2e
    ld hl, $c3cf
    jp Jump_000_2d7a


Call_01e_7eee:
jr_01e_7eee:
    ld a, $31
    ld [$cee6], a
    call Call_01e_7f02
    ld a, $cf
    ld [$cee6], a
    call Call_01e_7f02
    dec b
    jr nz, jr_01e_7eee

    ret


Call_01e_7f02:
    push bc
    xor a
    ldh [$ba], a
    ld hl, $c3cf
    ld bc, $0707
    ld de, $000d

jr_01e_7f0f:
    push bc

jr_01e_7f10:
    ld a, [$cee6]
    add [hl]
    ld [hl+], a
    dec c
    jr nz, jr_01e_7f10

    pop bc
    add hl, de
    dec b
    jr nz, jr_01e_7f0f

    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    pop bc
    ret


Call_01e_7f26:
jr_01e_7f26:
    call Call_000_0b31
    push bc
    call Call_000_3879
    ldh a, [$b5]
    pop bc
    and $02
    jr nz, jr_01e_7f39

jr_01e_7f34:
    dec c
    jr nz, jr_01e_7f26

    and a
    ret


jr_01e_7f39:
    ld a, [$ccd4]
    and a
    jr nz, jr_01e_7f34

    scf
    ret


    ld de, $ffe0
    call Call_01e_7f90
    ld de, $0240
    call Call_01e_7f90
    call Call_000_3e07
    ld a, $ff
    call Call_000_0e45
    ldh a, [$af]
    ld d, a
    ld e, $01
    ld b, $64

jr_01e_7f5c:
    ld a, e
    xor $fe
    ld e, a
    add d
    ldh [$af], a
    push bc
    ld c, $02
    ld a, $b4
    call Call_000_0e35
    pop bc
    ld c, $02
    call Call_000_3781
    dec b
    jr nz, jr_01e_7f5c

    ld a, d
    ldh [$af], a
    ld a, $ff
    call Call_000_0e45
    ld c, $02
    ld a, $b9
    call Call_000_0e35

jr_01e_7f83:
    ld a, [$c02a]
    cp $b9
    jr z, jr_01e_7f83

    call Call_000_0ebd
    jp Jump_000_0d9b


Call_01e_7f90:
    ld hl, $d4a6
    ld a, [hl-]
    push af
    ld a, [hl]
    push af
    push hl
    push hl
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    add hl, de
    ld a, h
    and $03
    or $98
    ld d, a
    ld a, l
    pop hl
    ld [hl+], a
    ld [hl], d
    call Call_000_28a2
    pop hl
    pop af
    ld [hl+], a
    pop af
    ld [hl], a
    jp Jump_000_3e07


    ld a, [$cf78]
    sub $c9
    ret c

    ld d, a
    ld hl, $7fd3
    srl a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    srl d
    jr nc, jr_01e_7fc9

    swap a

jr_01e_7fc9:
    and $f0
    ldh [$8c], a
    xor a
    ldh [$8b], a
    ldh [$8d], a
    ret


    ld [hl-], a
    ld hl, $2434
    inc [hl]
    ld hl, $5545
    ld [hl-], a
    ld [hl-], a
    ld d, l
    ld d, d
    ld d, h
    ld d, d
    ld b, c
    ld hl, $4212
    dec h
    inc h
    ld [hl+], a
    ld d, d
    inc h
    inc [hl]
    ld b, d
    ld bc, $2801
    jr nz, @+$44

    dec b
    nop
    jr nz, jr_01e_7ff9

    nop
    inc c
    ld b, c
    pop bc

jr_01e_7ff9:
    ld b, $a4
    add l
    jr nz, jr_01e_7fff

    ld [bc], a

jr_01e_7fff:
    nop
