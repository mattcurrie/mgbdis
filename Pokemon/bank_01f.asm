; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $01f", ROMX[$4000], BANK[$1f]

    db $ed
    nop
    adc h
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3408], a
    add sp, -$24
    or l
    db $e4
    ld b, l
    push hl
    sub b
    db $e4
    ld b, b
    dec h
    push hl
    ld [hl], b
    db $e4
    jr nz, @+$17

    push hl
    ld h, b
    db $e4
    db $10
    inc hl
    ld b, c
    db $10
    ld b, b
    db $10
    ret nz

    push hl
    ld b, b
    jp nz, Jump_01f_4040

    ld b, b
    ret nz

    ld b, b
    ret nz

    ld b, b
    jp nz, $c040

    ld b, b
    jp nz, Jump_01f_4040

    ld b, b
    ret nz

    ld b, b
    ret nz

    ld b, b
    ld b, b
    ld h, b
    ld [hl], b
    call c, $93b6
    ld b, c

Jump_01f_4040:
    sub c
    ld [hl], e
    sub c
    ld [hl], c
    or e
    sub e
    ld [hl], c
    ld h, c
    ld b, c
    ld hl, $4115
    sub e
    inc de
    ld b, e
    ld hl, $4111
    ld h, c
    ld [hl], c
    ld h, c
    sub e
    ld b, c
    sub c
    ld [hl], e
    sub c
    ld [hl], c
    or e
    sub e
    ld [hl], c
    sub c
    ld h, c
    ld hl, $1145
    sub e
    inc de
    ld b, e
    ld hl, $4111
    ld h, c
    ld [hl], c
    ld h, c
    ld [hl], e
    ld hl, $b171
    sub c
    ld [hl], c
    sub c
    inc hl
    ld b, c
    ld h, c
    ld [hl], c
    ld h, c
    ld b, c
    ld hl, $9145
    ld [hl], e
    ld h, e
    ld [hl], e
    ld h, e
    ld b, e
    inc hl
    ld [hl], e
    ld hl, $b171
    db $e4
    ld de, $b1e5
    sub c
    inc hl
    ld b, c
    ld h, c
    ld [hl], c
    ld h, c
    ld b, c
    ld hl, $b7dc
    ld b, l
    sub c
    ld [hl], e
    ld h, e
    call c, $93c7
    or e
    db $e4
    inc de
    inc hl
    push hl
    or c

Call_01f_40a1:
    sub c
    ld [hl], c
    ld h, c
    ld b, c
    ld h, c
    ld [hl], c
    sub c
    call c, Call_01f_7790
    ld h, a
    ld b, a
    daa
    rst $08
    rst $08
    rst $00
    call c, $45b6
    jr nc, jr_01f_40d6

    call c, Call_000_17a0
    call c, $17a7
    rst $08
    rst $08
    rst $00
    ld b, l
    db $10
    ld b, b
    call c, $97a0
    call c, $97a7
    call c, Call_01f_75b6
    inc hl
    ld [hl], c
    or e
    call c, Call_01f_77b7
    ld h, e
    add e
    call c, $9790

jr_01f_40d6:
    ld h, a
    ld b, a
    rla
    call c, Call_000_27b7
    rla
    and $b7
    push hl
    daa
    call c, $4790

Jump_01f_40e4:
    daa

Jump_01f_40e5:
    ld h, a
    ld b, a

Jump_01f_40e7:
    call c, Call_000_27a0
    ld b, a
    daa
    rlca
    ld [hl], a
    ld d, a
    ld b, a
    daa
    call c, Call_000_15a0
    call c, Call_000_15a7
    call c, Call_000_23b7
    ld b, a
    ld [hl], l
    ld h, b
    ld d, b
    call c, Call_01f_45a0
    call c, Call_01f_45a7
    call c, Call_000_23b7
    call c, Call_000_17a0
    call c, $17a7
    call c, Call_01f_45b7
    ld hl, $6373
    ld b, e
    ld h, e
    ld b, e
    inc hl
    ld b, e
    inc hl
    inc de
    inc hl
    inc de
    inc de
    ld b, e
    ld h, e
    call c, Call_01f_45a0
    call c, Call_000_21b7
    ld [hl], e
    ld h, e
    ld b, e
    ld h, e
    sub e
    or e
    call c, $e4a0
    rra
    rla
    call c, $17a7
    call c, $e5b5
    sub b
    ret nz

    sub b
    jp nz, $9090

    call c, $97b1
    rst $38
    db $ec
    inc bc
    ld [$250a], a
    call c, $e4c5
    sub l
    ld b, b
    sub b
    ld [hl], l
    jr nz, jr_01f_41be

    call c, $6bc7
    add c
    ld b, b
    add b
    call c, $91c2
    call c, $e5c1
    sub e
    sub b
    sub b
    sub c
    sub c
    sub e
    sub c
    sub e
    sub b
    sub b
    sub c
    sub c
    call c, $90c4
    ld h, b
    sub b
    or b
    call c, $e4c7
    dec d
    db $10
    jr nz, jr_01f_41b6

    inc de
    ld [hl], e
    ld h, e
    ld b, e
    inc hl
    dec d
    push hl
    sub c
    db $e4
    ld b, a
    push hl
    sub l
    ld b, c
    db $e4
    rla
    dec d
    db $10
    jr nz, jr_01f_41c9

    inc de
    ld [hl], e
    ld h, e
    ld b, e
    inc hl
    dec d
    push hl
    sub c
    db $e4
    ld b, a
    push hl
    sub l
    ld b, c
    call c, $e4b0
    rla
    call c, $25c7
    push hl
    or c
    db $e4
    ld [hl], a
    push hl
    ld [hl], l
    ld hl, $dcb7
    or b

Call_01f_41a4:
    db $e4
    dec d
    call c, Call_000_15b7
    inc hl
    call c, $47a0
    call c, $47a7
    call c, $25c7
    push hl
    or c
    db $e4

jr_01f_41b6:
    ld [hl], a
    push hl
    ld [hl], l
    ld hl, $dcb7
    or b
    db $e4

jr_01f_41be:
    ld b, [hl]
    call c, $46b7
    call c, $40c3
    add b
    call c, $97b0

jr_01f_41c9:
    call c, $97b7
    call c, Call_01f_73c6
    ld h, e
    ld b, e
    inc hl
    call c, Call_000_17a0
    call c, $17a7
    call c, $e590
    sub a
    call c, $9797
    call c, Call_01f_47b0
    call c, $47b7
    call c, Call_000_27c7
    ld [hl], l
    ld h, b
    ld d, b
    ld b, a
    call c, Call_01f_75b7
    ld h, b
    ld d, b
    call c, Call_01f_47b0
    call c, $47b7
    call c, $27b0
    call c, Call_000_27b7

jr_01f_41fd:
    call c, $e6c7
    or a
    push hl
    ld h, l
    jr nz, jr_01f_4265

    ld b, a
    or l
    ld [hl], b
    or b
    call c, $e4b0
    rla
    call c, $17b7
    call c, $27b0
    call c, Call_000_27b7
    call c, $e5c7
    or a
    db $e4
    dec h
    push hl
    or b
    db $e4
    jr nz, jr_01f_41fd

    or b
    dec d
    call c, Call_000_15b7
    call c, $e5c7
    or e
    call c, $97b0
    call c, $97b7
    call c, Call_01f_65b0
    call c, Call_01f_65b7
    call c, $83c7
    sub a
    ld h, a
    call c, $85b0
    call c, $85b7
    call c, $93c7
    or a
    add a
    call c, $95b0
    call c, $95b7
    call c, $b3c7
    db $e4
    rlca
    push hl
    sub a
    call c, $b5b0
    call c, $b5b7
    call c, $e4c7
    inc bc
    call c, $27b0
    push hl
    or a
    call c, $e4b0

jr_01f_4265:
    rra
    rla
    call c, $17b7
    call c, $e5b0
    sbc a
    sub a
    call c, $97b7
    call c, Call_01f_75c7
    or c
    db $e4
    daa
    push hl
    or l
    db $e4
    ld hl, $6075
    ld d, b
    ld b, a
    push hl
    ld [hl], l
    ld h, b
    ld d, b
    ld b, a
    inc de
    inc hl
    ld [hl], l
    or c
    db $e4
    daa
    push hl
    or l
    db $e4
    ld hl, $dc77
    or b
    sbc a
    call c, $97a0
    call c, $97a7
    call c, $91c1
    sub e
    sub b
    sub b
    call c, $97c1
    rst $38
    call c, $e310
    dec d
    db $e4
    sub b
    db $e3
    db $10
    dec h
    db $e4
    or b
    db $e3
    jr nz, jr_01f_4316

    jr nz, jr_01f_4313

    sub e
    add c
    ld b, b
    add b

Call_01f_42b7:
    sub b
    adc $cf
    db $fd
    add l
    ld b, e
    db $fd
    adc a
    ld b, e
    db $fd
    add l
    ld b, e
    db $e4
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    ld h, c
    ld [hl], c
    sub c
    db $fd
    add l
    ld b, e
    db $fd
    adc a
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    sbc c
    ld b, e
    db $fd
    sbc c
    ld b, e
    db $fd
    and d
    ld b, e
    db $e4
    sub c
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    db $e3
    ld de, $b1e4
    sub c
    db $fd
    sbc c
    ld b, e
    db $fd
    sbc c
    ld b, e
    db $fd
    and d
    ld b, e
    db $fd
    and d
    ld b, e
    db $e4
    ld [hl], e
    sub e
    or e
    db $e3
    inc hl
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    add l

jr_01f_4313:
    ld b, e
    db $fd
    adc a

jr_01f_4316:
    ld b, e
    db $fd
    adc a
    ld b, e
    db $fd
    add l
    ld b, e
    ld b, e
    sub c
    ld b, e
    sub c
    ld b, c
    sub c
    db $fd
    adc a
    ld b, e
    db $fd
    adc a
    ld b, e
    db $fd
    add l
    ld b, e
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    add c
    sub c
    db $fd
    or e
    ld b, e
    db $fd
    or e
    ld b, e
    db $fd
    cp h
    ld b, e
    db $fd
    cp h
    ld b, e
    ld d, c
    sub c
    ld d, c
    sub c
    ld d, c
    sub c
    ld d, c

Jump_01f_4347:
    sub c
    ld d, c
    sub c
    ld [hl], c
    ld d, c
    ld b, c
    ld hl, $5141
    db $fd
    sbc c
    ld b, e
    db $fd
    sbc c
    ld b, e
    ld b, e
    sub e
    ld b, e
    sub e
    ld b, e
    sub e
    ld b, e
    sub e
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    push bc
    ld b, e

Jump_01f_4367:
    db $fd
    push bc
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    add l
    ld b, e
    db $fd
    sbc c
    ld b, e
    db $fd
    sbc c
    ld b, e
    db $fd
    adc $43
    db $fd
    adc $43
    sub b
    ret nz

    sub b
    jp nz, $9090

    sub b
    add $ff
    db $e4
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    rst $38
    db $e4
    ld hl, $2171
    ld [hl], c
    ld hl, $2171
    ld [hl], c
    rst $38
    ld [hl], c
    or c
    ld [hl], c
    or c
    ld [hl], c
    or c
    ld [hl], c
    or c
    rst $38
    db $e4

Jump_01f_43a3:
    sub c
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    db $e3
    ld de, $21ff
    sub c
    ld hl, $2191
    sub c
    ld hl, $ff91
    ld b, c
    add c
    ld b, c
    add c

Call_01f_43c0:
    ld b, c
    add c

Call_01f_43c2:
    ld b, c

Jump_01f_43c3:
    add c
    rst $38
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    rst $38
    sub b
    ret nz

    sub b
    jp nz, $9090

    sub b
    ret nz

Jump_01f_43d6:
    sub b
    ret nz

    sub b
    jp nz, $f0ff

    call c, Call_000_000e
    ld hl, $4410

jr_01f_43e2:
    cp [hl]

Jump_01f_43e3:
    jr c, jr_01f_43e9

    inc c
    inc hl
    jr jr_01f_43e2

jr_01f_43e9:
    push bc
    ld a, $ff
    ld [$c0ee], a
    call Call_000_3788
    pop bc
    ld b, $00
    ld hl, $4402
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld c, [hl]
    call Call_000_0e35
    jp Jump_000_0d9b


    and l
    rra
    sub c
    ld [bc], a
    add [hl]
    ld [bc], a
    sbc d
    ld [$0886], sp
    sub h
    ld [bc], a
    adc c
    ld [bc], a
    ld a, [bc]
    jr z, @+$3e

    ld e, d
    ld a, b
    sub [hl]
    rst $38
    ld c, $00

jr_01f_4419:
    ld b, $00
    ld hl, $c026
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_01f_4445

    ld a, c
    cp $04
    jr nc, jr_01f_4442

    ld a, [$c002]
    and a
    jr z, jr_01f_4442

    bit 7, a
    jr nz, jr_01f_4445

    set 7, a
    ld [$c002], a
    xor a
    ldh [rNR51], a
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a
    jr jr_01f_4445

jr_01f_4442:
    call Call_01f_444c

jr_01f_4445:
    ld a, c
    inc c
    cp $07
    jr nz, jr_01f_4419

    ret


Call_01f_444c:
    ld b, $00
    ld hl, $c0b6
    add hl, bc
    ld a, [hl]
    cp $01
    jp z, Jump_01f_44e4

    dec a
    ld [hl], a
    ld a, c
    cp $04
    jr nc, jr_01f_4468

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_01f_4468

    ret


jr_01f_4468:
    ld hl, $c02e
    add hl, bc
    bit 6, [hl]
    jr z, jr_01f_4473

    call Call_01f_4b21

jr_01f_4473:
    ld b, $00
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_01f_4485

    ld hl, $c02e
    add hl, bc
    bit 2, [hl]
    jr nz, jr_01f_4499

jr_01f_4485:
    ld hl, $c02e
    add hl, bc
    bit 4, [hl]
    jr z, jr_01f_4490

    jp Jump_01f_4a0d


jr_01f_4490:
    ld hl, $c04e
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_01f_449a

    dec [hl]

jr_01f_4499:
    ret


jr_01f_449a:
    ld hl, $c056
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_01f_44a3

    ret


jr_01f_44a3:
    ld d, a
    ld hl, $c05e
    add hl, bc
    ld a, [hl]
    and $0f
    and a
    jr z, jr_01f_44b0

    dec [hl]
    ret


jr_01f_44b0:
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
    jr z, jr_01f_44d0

    res 3, [hl]
    ld a, d
    and $0f
    ld d, a
    ld a, e
    sub d
    jr nc, jr_01f_44ce

    ld a, $00

jr_01f_44ce:
    jr jr_01f_44dc

jr_01f_44d0:
    set 3, [hl]
    ld a, d
    and $f0
    swap a
    add e
    jr nc, jr_01f_44dc

    ld a, $ff

jr_01f_44dc:
    ld d, a
    ld b, $03
    call Call_01f_4b4c
    ld [hl], d
    ret


Jump_01f_44e4:
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
    call Call_01f_44fa
    ret


Call_01f_44fa:
Jump_01f_44fa:
    call Call_01f_4b39
    ld d, a
    cp $ff
    jp nz, Jump_01f_4588

    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 1, [hl]
    jr nz, jr_01f_4538

    ld a, c
    cp $03
    jr nc, jr_01f_4514

    jr jr_01f_4553

jr_01f_4514:
    res 2, [hl]
    ld hl, $c036
    add hl, bc
    res 0, [hl]
    cp $06
    jr nz, jr_01f_4528

    ld a, $00
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a

jr_01f_4528:
    jr nz, jr_01f_4536

    ld a, [$c003]
    and a
    jr z, jr_01f_4536

    xor a
    ld [$c003], a
    jr jr_01f_4553

jr_01f_4536:
    jr jr_01f_455c

jr_01f_4538:
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
    jp Jump_01f_44fa


jr_01f_4553:
    ld hl, $4e33
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a

jr_01f_455c:
    ld a, [$c02a]
    cp $14
    jr nc, jr_01f_4565

    jr jr_01f_4582

jr_01f_4565:
    ld a, [$c02a]
    cp $86
    jr z, jr_01f_4582

    jr c, jr_01f_4570

    jr jr_01f_4582

jr_01f_4570:
    ld a, c
    cp $04
    jr z, jr_01f_4579

    call Call_01f_49db
    ret c

jr_01f_4579:
    ld a, [$c005]
    ldh [rNR50], a
    xor a
    ld [$c005], a

jr_01f_4582:
    ld hl, $c026
    add hl, bc
    ld [hl], b
    ret


Jump_01f_4588:
    cp $fd
    jp nz, Jump_01f_45bd

    call Call_01f_4b39
    push af
    call Call_01f_4b39
    ld d, a
    pop af
    ld e, a
    push de
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, $c006

Call_01f_45a0:
    add hl, de
    push hl
    ld hl, $c016
    add hl, de
    ld e, l

Call_01f_45a7:
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

Call_01f_45b7:
    add hl, bc
    set 1, [hl]
    jp Jump_01f_44fa


Jump_01f_45bd:
    cp $fe
    jp nz, Jump_01f_45f8

    call Call_01f_4b39
    ld e, a
    and a
    jr z, jr_01f_45e1

    ld b, $00
    ld hl, $c0be
    add hl, bc
    ld a, [hl]
    cp e
    jr nz, jr_01f_45df

    ld a, $01
    ld [hl], a
    call Call_01f_4b39
    call Call_01f_4b39
    jp Jump_01f_44fa


jr_01f_45df:
    inc a
    ld [hl], a

jr_01f_45e1:
    call Call_01f_4b39
    push af
    call Call_01f_4b39
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
    jp Jump_01f_44fa


Jump_01f_45f8:
    and $f0
    cp $d0
    jp nz, Jump_01f_4637

    ld a, d
    and $0f
    ld b, $00
    ld hl, $c0c6
    add hl, bc
    ld [hl], a
    ld a, c
    cp $03
    jr z, jr_01f_4634

    call Call_01f_4b39
    ld d, a
    ld a, c
    cp $02
    jr z, jr_01f_4620

    cp $06
    jr nz, jr_01f_462d

    ld hl, $c0e7
    jr jr_01f_4623

jr_01f_4620:
    ld hl, $c0e6

jr_01f_4623:
    ld a, d
    and $0f
    ld [hl], a
    ld a, d
    and $30
    sla a
    ld d, a

jr_01f_462d:
    ld b, $00
    ld hl, $c0de
    add hl, bc
    ld [hl], d

jr_01f_4634:
    jp Jump_01f_44fa


Jump_01f_4637:
    ld a, d
    cp $e8
    jr nz, jr_01f_4649

    ld b, $00
    ld hl, $c02e
    add hl, bc
    ld a, [hl]
    xor $01
    ld [hl], a
    jp Jump_01f_44fa


jr_01f_4649:
    cp $ea
    jr nz, jr_01f_4681

    call Call_01f_4b39
    ld b, $00
    ld hl, $c04e
    add hl, bc
    ld [hl], a
    ld hl, $c06e
    add hl, bc
    ld [hl], a
    call Call_01f_4b39
    ld d, a
    and $f0
    swap a
    ld b, $00
    ld hl, $c056
    add hl, bc
    srl a
    ld e, a
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
    jp Jump_01f_44fa


jr_01f_4681:
    cp $eb
    jr nz, jr_01f_46b9

    call Call_01f_4b39
    ld b, $00
    ld hl, $c076
    add hl, bc
    ld [hl], a
    call Call_01f_4b39
    ld d, a
    and $f0
    swap a
    ld b, a
    ld a, d
    and $0f
    call Call_01f_4b6c
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
    call Call_01f_4b39
    ld d, a
    jp Jump_01f_481e


jr_01f_46b9:
    cp $ec
    jr nz, jr_01f_46ce

    call Call_01f_4b39
    rrca
    rrca
    and $c0
    ld b, $00
    ld hl, $c03e
    add hl, bc
    ld [hl], a
    jp Jump_01f_44fa


jr_01f_46ce:
    cp $ed
    jr nz, jr_01f_470e

    ld a, c
    cp $04
    jr nc, jr_01f_46f2

    call Call_01f_4b39
    ld [$c0e8], a
    call Call_01f_4b39
    ld [$c0e9], a
    xor a
    ld [$c0ce], a
    ld [$c0cf], a
    ld [$c0d0], a
    ld [$c0d1], a
    jr jr_01f_470b

jr_01f_46f2:
    call Call_01f_4b39
    ld [$c0ea], a
    call Call_01f_4b39
    ld [$c0eb], a
    xor a
    ld [$c0d2], a
    ld [$c0d3], a
    ld [$c0d4], a
    ld [$c0d5], a

jr_01f_470b:
    jp Jump_01f_44fa


jr_01f_470e:
    cp $ee
    jr nz, jr_01f_471b

    call Call_01f_4b39
    ld [$c004], a
    jp Jump_01f_44fa


jr_01f_471b:
    cp $ef
    jr nz, jr_01f_473a

    call Call_01f_4b39
    push bc
    call Call_01f_4b8a
    pop bc
    ld a, [$c003]
    and a
    jr nz, jr_01f_4737

    ld a, [$c02d]
    ld [$c003], a
    xor a
    ld [$c02d], a

jr_01f_4737:
    jp Jump_01f_44fa


jr_01f_473a:
    cp $fc
    jr nz, jr_01f_4758

    call Call_01f_4b39
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
    jp Jump_01f_44fa


jr_01f_4758:
    cp $f0
    jr nz, jr_01f_4764

    call Call_01f_4b39
    ldh [rNR50], a
    jp Jump_01f_44fa


jr_01f_4764:
    cp $f8
    jr nz, jr_01f_4773

    ld b, $00
    ld hl, $c036
    add hl, bc
    set 0, [hl]
    jp Jump_01f_44fa


jr_01f_4773:
    and $f0
    cp $e0
    jr nz, jr_01f_4786

    ld hl, $c0d6
    ld b, $00
    add hl, bc
    ld a, d
    and $0f
    ld [hl], a
    jp Jump_01f_44fa


jr_01f_4786:
    cp $20
    jr nz, jr_01f_47d3

    ld a, c
    cp $03
    jr c, jr_01f_47d3

    ld b, $00
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_01f_47d3

    call Call_01f_481e
    ld d, a
    ld b, $00
    ld hl, $c03e
    add hl, bc
    ld a, [hl]
    or d
    ld d, a
    ld b, $01
    call Call_01f_4b4c
    ld [hl], d
    call Call_01f_4b39
    ld d, a

Call_01f_47b0:
    ld b, $02
    call Call_01f_4b4c
    ld [hl], d
    call Call_01f_4b39
    ld e, a
    ld a, c
    cp $07
    ld a, $00
    jr z, jr_01f_47c6

    push de
    call Call_01f_4b39
    pop de

jr_01f_47c6:
    ld d, a
    push de
    call Call_01f_493d
    call Call_01f_490c
    pop de
    call Call_01f_495f
    ret


jr_01f_47d3:
    ld a, c
    cp $04

Call_01f_47d6:
    jr c, jr_01f_47ef

    ld a, d
    cp $10
    jr nz, jr_01f_47ef

    ld b, $00
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_01f_47ef

    call Call_01f_4b39
    ldh [rNR10], a
    jp Jump_01f_44fa


jr_01f_47ef:
    ld a, c
    cp $03
    jr nz, jr_01f_481e

    ld a, d
    and $f0
    cp $b0
    jr z, jr_01f_4809

    jr nc, jr_01f_481e

    swap a
    ld b, a
    ld a, d
    and $0f
    ld d, a
    ld a, b
    push de
    push bc
    jr jr_01f_4811

jr_01f_4809:
    ld a, d
    and $0f
    push af
    push bc
    call Call_01f_4b39

jr_01f_4811:
    ld d, a
    ld a, [$c003]
    and a
    jr nz, jr_01f_481c

    ld a, d
    call Call_01f_4b8a

jr_01f_481c:
    pop bc
    pop de

Call_01f_481e:
Jump_01f_481e:
jr_01f_481e:
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
    call Call_01f_4b5b
    ld a, c
    cp $04
    jr nc, jr_01f_483f

    ld a, [$c0e8]
    ld d, a
    ld a, [$c0e9]
    ld e, a
    jr jr_01f_4852

jr_01f_483f:
    ld d, $01
    ld e, $00
    cp $07
    jr z, jr_01f_4852

    call Call_01f_49a7
    ld a, [$c0ea]
    ld d, a
    ld a, [$c0eb]
    ld e, a

jr_01f_4852:
    ld a, l
    ld b, $00
    ld hl, $c0ce
    add hl, bc
    ld l, [hl]
    call Call_01f_4b5b
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
    jr nz, jr_01f_487c

    ld hl, $c02e
    add hl, bc
    bit 2, [hl]
    jr z, jr_01f_487c

    pop hl
    ret


jr_01f_487c:
    pop af
    and $f0
    cp $c0
    jr nz, jr_01f_48b3

    ld a, c
    cp $04
    jr nc, jr_01f_4890

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_01f_48b2

jr_01f_4890:
    ld a, c
    cp $02
    jr z, jr_01f_4899

    cp $06
    jr nz, jr_01f_48a6

jr_01f_4899:
    ld b, $00
    ld hl, $4e33
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a
    jr jr_01f_48b2

jr_01f_48a6:
    ld b, $02
    call Call_01f_4b4c
    ld a, $08
    ld [hl+], a
    inc hl
    ld a, $80
    ld [hl], a

jr_01f_48b2:
    ret


jr_01f_48b3:
    swap a
    ld b, $00
    ld hl, $c0d6
    add hl, bc
    ld b, [hl]
    call Call_01f_4b6c
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 4, [hl]
    jr z, jr_01f_48cc

    call Call_01f_4aa3

jr_01f_48cc:
    push de
    ld a, c
    cp $04
    jr nc, jr_01f_48e1

    ld hl, $c02a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    and a
    jr nz, jr_01f_48df

    jr jr_01f_48e1

jr_01f_48df:
    pop de
    ret


jr_01f_48e1:
    ld b, $00
    ld hl, $c0de
    add hl, bc
    ld d, [hl]
    ld b, $02
    call Call_01f_4b4c
    ld [hl], d
    call Call_01f_493d
    call Call_01f_490c
    pop de
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 0, [hl]
    jr z, jr_01f_4903

    inc e
    jr nc, jr_01f_4903

    inc d

jr_01f_4903:
    ld hl, $c066
    add hl, bc
    ld [hl], e
    call Call_01f_495f
    ret


Call_01f_490c:
    ld b, $00
    ld hl, $4e3b
    add hl, bc
    ldh a, [rNR51]
    or [hl]
    ld d, a
    ld a, c
    cp $07
    jr z, jr_01f_4927

    cp $04
    jr nc, jr_01f_4939

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_01f_4939

jr_01f_4927:
    ld a, [$c004]
    ld hl, $4e3b
    add hl, bc
    and [hl]
    ld d, a
    ldh a, [rNR51]
    ld hl, $4e33
    add hl, bc
    and [hl]
    or d
    ld d, a

jr_01f_4939:
    ld a, d
    ldh [rNR51], a
    ret


Call_01f_493d:
    ld b, $00
    ld hl, $c0b6
    add hl, bc
    ld d, [hl]
    ld a, c
    cp $02
    jr z, jr_01f_4958

    cp $06
    jr z, jr_01f_4958

    ld a, d
    and $3f
    ld d, a
    ld hl, $c03e
    add hl, bc
    ld a, [hl]
    or d
    ld d, a

jr_01f_4958:
    ld b, $01
    call Call_01f_4b4c
    ld [hl], d
    ret


Call_01f_495f:
    ld a, c
    cp $02
    jr z, jr_01f_4968

    cp $06
    jr nz, jr_01f_4995

jr_01f_4968:
    push de
    ld de, $c0e6
    cp $02
    jr z, jr_01f_4973

    ld de, $c0e7

jr_01f_4973:
    ld a, [de]
    add a
    ld d, $00
    ld e, a
    ld hl, $7220
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld hl, $ff30
    ld b, $0f
    ld a, $00
    ldh [rNR30], a

jr_01f_4988:
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, b
    dec b
    and a
    jr nz, jr_01f_4988

    ld a, $80
    ldh [rNR30], a
    pop de

jr_01f_4995:
    ld a, d
    or $80
    and $c7
    ld d, a
    ld b, $03
    call Call_01f_4b4c
    ld [hl], e
    inc hl
    ld [hl], d
    call Call_01f_49c9
    ret


Call_01f_49a7:
    call Call_01f_49f9
    jr nc, jr_01f_49bf

    ld d, $00
    ld a, [$c0f2]
    add $80
    jr nc, jr_01f_49b6

    inc d

jr_01f_49b6:
    ld [$c0eb], a
    ld a, d
    ld [$c0ea], a
    jr jr_01f_49c8

jr_01f_49bf:
    xor a
    ld [$c0eb], a
    ld a, $01
    ld [$c0ea], a

jr_01f_49c8:
    ret


Call_01f_49c9:
    call Call_01f_49f9
    jr nc, jr_01f_49da

    ld a, [$c0f1]
    add e
    jr nc, jr_01f_49d5

    inc d

jr_01f_49d5:
    dec hl
    ld e, a
    ld [hl], e
    inc hl
    ld [hl], d

jr_01f_49da:
    ret


Call_01f_49db:
    call Call_01f_49f9
    jr nc, jr_01f_49f6

    ld hl, $c006
    ld e, c
    ld d, $00
    sla e
    rl d
    add hl, de
    ld a, [hl]
    sub $01
    ld [hl], a
    inc hl
    ld a, [hl]
    sbc $00
    ld [hl], a
    scf
    ret


jr_01f_49f6:
    scf
    ccf
    ret


Call_01f_49f9:
    ld a, [$c02a]
    cp $14
    jr nc, jr_01f_4a02

    jr jr_01f_4a08

jr_01f_4a02:
    cp $86
    jr z, jr_01f_4a08

    jr c, jr_01f_4a0b

jr_01f_4a08:
    scf
    ccf
    ret


jr_01f_4a0b:
    scf
    ret


Jump_01f_4a0d:
    ld hl, $c02e
    add hl, bc
    bit 5, [hl]
    jp nz, Jump_01f_4a54

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
    jp c, Jump_01f_4a9a

    jr nz, jr_01f_4a87

    ld hl, $c0ae
    add hl, bc
    ld a, [hl]
    cp e
    jp c, Jump_01f_4a9a

    jr jr_01f_4a87

Jump_01f_4a54:
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
    jr c, jr_01f_4a9a

    jr nz, jr_01f_4a87

    ld hl, $c0ae
    add hl, bc
    ld a, e
    cp [hl]
    jr c, jr_01f_4a9a

jr_01f_4a87:
    ld hl, $c09e
    add hl, bc
    ld [hl], e
    ld hl, $c096
    add hl, bc
    ld [hl], d
    ld b, $03
    call Call_01f_4b4c
    ld a, e
    ld [hl+], a
    ld [hl], d
    ret


Jump_01f_4a9a:
jr_01f_4a9a:
    ld hl, $c02e
    add hl, bc
    res 4, [hl]
    res 5, [hl]
    ret


Call_01f_4aa3:
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
    jr nc, jr_01f_4abb

    ld a, $01

jr_01f_4abb:
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
    jr c, jr_01f_4ad7

    ld d, a
    ld b, $00
    ld hl, $c02e
    add hl, bc
    set 5, [hl]
    jr jr_01f_4afa

jr_01f_4ad7:
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

jr_01f_4afa:
    ld hl, $c076
    add hl, bc

jr_01f_4afe:
    inc b
    ld a, e
    sub [hl]
    ld e, a
    jr nc, jr_01f_4afe

    ld a, d
    and a
    jr z, jr_01f_4b0c

    dec a
    ld d, a
    jr jr_01f_4afe

jr_01f_4b0c:
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


Call_01f_4b21:
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
    call Call_01f_4b4c
    ld a, [hl]
    and $3f
    or d
    ld [hl], a
    ret


Call_01f_4b39:
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


Call_01f_4b4c:
    ld a, c
    ld hl, $4e2b
    add l
    jr nc, jr_01f_4b54

    inc h

jr_01f_4b54:
    ld l, a
    ld a, [hl]
    add b
    ld l, a
    ld h, $ff
    ret


Call_01f_4b5b:
    ld h, $00

jr_01f_4b5d:
    srl a
    jr nc, jr_01f_4b62

    add hl, de

jr_01f_4b62:
    sla e
    rl d
    and a
    jr z, jr_01f_4b6b

    jr jr_01f_4b5d

jr_01f_4b6b:
    ret


Call_01f_4b6c:
    ld h, $00
    ld l, a
    add hl, hl
    ld d, h
    ld e, l
    ld hl, $4e43
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld a, b

jr_01f_4b7a:
    cp $07
    jr z, jr_01f_4b85

    sra d
    rr e
    inc a
    jr jr_01f_4b7a

jr_01f_4b85:
    ld a, $08
    add d
    ld d, a
    ret


Call_01f_4b8a:
    ld [$c001], a
    cp $ff
    jp z, Jump_01f_4d48

    cp $c2
    jp z, Jump_01f_4c62

    jp c, Jump_01f_4c62

    cp $fe
    jr z, jr_01f_4ba1

    jp nc, Jump_01f_4c62

jr_01f_4ba1:
    xor a
    ld [$c000], a
    ld [$c003], a
    ld [$c0e9], a
    ld [$c0e6], a
    ld [$c0e7], a
    ld d, $08
    ld hl, $c016
    call Call_01f_4d9d
    ld hl, $c006
    call Call_01f_4d9d
    ld d, $04
    ld hl, $c026
    call Call_01f_4d9d
    ld hl, $c02e
    call Call_01f_4d9d
    ld hl, $c03e
    call Call_01f_4d9d
    ld hl, $c046
    call Call_01f_4d9d
    ld hl, $c04e
    call Call_01f_4d9d
    ld hl, $c056
    call Call_01f_4d9d
    ld hl, $c05e
    call Call_01f_4d9d
    ld hl, $c066
    call Call_01f_4d9d
    ld hl, $c06e
    call Call_01f_4d9d
    ld hl, $c036
    call Call_01f_4d9d
    ld hl, $c076
    call Call_01f_4d9d
    ld hl, $c07e
    call Call_01f_4d9d
    ld hl, $c086
    call Call_01f_4d9d
    ld hl, $c08e
    call Call_01f_4d9d
    ld hl, $c096
    call Call_01f_4d9d
    ld hl, $c09e
    call Call_01f_4d9d
    ld hl, $c0a6
    call Call_01f_4d9d
    ld hl, $c0ae
    call Call_01f_4d9d
    ld a, $01
    ld hl, $c0be
    call Call_01f_4d9d
    ld hl, $c0b6
    call Call_01f_4d9d
    ld hl, $c0c6
    call Call_01f_4d9d
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
    jp Jump_01f_4da3


Jump_01f_4c62:
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, $6ebf
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

Jump_01f_4c7b:
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
    jr z, jr_01f_4cb7

    ld a, e
    cp $07
    jr nz, jr_01f_4cae

    ld a, [$c001]
    cp $14
    jr nc, jr_01f_4ca7

    ret


jr_01f_4ca7:
    ld a, [hl]
    cp $14
    jr z, jr_01f_4cb7

    jr c, jr_01f_4cb7

jr_01f_4cae:
    ld a, [$c001]
    cp [hl]
    jr z, jr_01f_4cb7

    jr c, jr_01f_4cb7

    ret


jr_01f_4cb7:
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
    jr nz, jr_01f_4d3f

    ld a, $08
    ldh [rNR10], a

jr_01f_4d3f:
    ld a, c
    and a
    jp z, Jump_01f_4da3

    dec c
    jp Jump_01f_4c7b


Jump_01f_4d48:
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
    call Call_01f_4d9d
    ld a, $01
    ld d, $18
    ld hl, $c0b6
    call Call_01f_4d9d
    ld [$c0e8], a
    ld [$c0ea], a
    ld a, $ff
    ld [$c004], a
    ret


Call_01f_4d9d:
    ld b, d

jr_01f_4d9e:
    ld [hl+], a
    dec b
    jr nz, jr_01f_4d9e

    ret


Jump_01f_4da3:
    ld a, [$c001]
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, $6ebf
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

jr_01f_4dc5:
    cp c
    jr z, jr_01f_4dcd

    inc c
    inc hl
    inc hl
    jr jr_01f_4dc5

jr_01f_4dcd:
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
    jr c, jr_01f_4de6

    ld hl, $c02e
    add hl, bc
    set 2, [hl]

jr_01f_4de6:
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
    jr nz, jr_01f_4dc5

    ld a, [$c001]
    cp $14
    jr nc, jr_01f_4dff

    jr jr_01f_4e29

jr_01f_4dff:
    ld a, [$c001]
    cp $86
    jr z, jr_01f_4e29

    jr c, jr_01f_4e0a

    jr jr_01f_4e29

jr_01f_4e0a:
    ld hl, $c02a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld hl, $c012
    ld de, $4e2a
    ld [hl], e
    inc hl
    ld [hl], d
    ld a, [$c005]
    and a
    jr nz, jr_01f_4e29

    ldh a, [rNR50]
    ld [$c005], a
    ld a, $77
    ldh [rNR50], a

jr_01f_4e29:
    ret


    rst $38
    db $10
    dec d
    ld a, [de]
    rra
    db $10
    dec d
    ld a, [de]
    rra
    xor $dd
    cp e
    ld [hl], a
    xor $dd
    cp e
    ld [hl], a
    ld de, $4422
    adc b
    ld de, $4422
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
    jp c, $edfb

    nop
    sub b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$1408], a
    call c, $e5b5
    ld [hl], c
    db $e4
    inc bc
    inc hl
    ld b, c
    ld bc, $7141
    ld [hl], c
    ld d, c
    ld b, c
    ld d, e
    ld b, c
    ld hl, $2353
    push hl
    or c
    db $e4
    ld d, e
    inc hl
    ld b, c
    ld d, c
    ld [hl], c
    ld bc, $0141
    ld hl, $dc41
    or [hl]
    ld e, c
    call c, Call_01f_51a6
    ld b, c
    ld d, c
    ld a, c
    ld b, c
    ld hl, $5541
    add sp, -$24
    or e
    ld b, c
    ld hl, $4020
    ld d, c
    ld b, b
    ld d, b
    add sp, -$24
    or l
    ld [hl], l
    ld [hl], l
    sub c
    ld d, c
    ld [hl], l
    call c, Call_01f_71b4
    ld d, e
    call c, Call_01f_41a4
    ld hl, $93dc
    push hl
    sub c
    db $e4
    inc bc
    ld bc, $b1e5
    sub b
    or b
    sub c
    or c
    db $e4
    ld bc, $0103
    push hl
    sub c
    or c
    or c
    sub c
    db $e4
    inc bc
    push hl
    sub c
    or b
    db $e4
    nop
    push hl
    or c
    db $e4
    inc hl
    push hl
    or c
    db $e4
    inc bc
    push hl
    or b
    db $e4
    nop
    jr nz, @-$19

    or b
    db $e4
    inc bc
    call c, $033d
    call c, Call_01f_55b4
    ld [hl], e
    ld d, b
    ld [hl], b
    ld d, e
    ld b, l
    ld d, c
    ld b, c
    jr nz, jr_01f_4f29

    ld hl, $dc01
    or l
    push hl
    sub e
    db $e4
    inc hl
    push hl
    or e
    db $e4
    ld b, e
    inc bc
    ld d, e
    inc hl
    ld h, e
    ld [$260a], a
    call c, Call_01f_7f80
    ld [hl], e
    call c, $7b87
    call c, $eab5
    ld [$fe14], sp
    nop
    ld l, c
    ld c, [hl]
    db $ec
    ld [bc], a
    ld [$1506], a
    call c, $e4c3
    ld bc, $5343
    ld [hl], e
    db $e3
    inc bc
    db $e4
    or l
    sub b
    or b
    sbc c
    ld d, c
    ld [hl], c
    sub c
    db $e3
    ld hl, $e401
    or c
    sub b
    or b

jr_01f_4f29:
    db $e3
    dec b
    db $e4
    sub c
    ld [hl], e
    db $ec
    inc bc
    call c, $a584
    db $ec
    ld [bc], a
    call c, $e3c5
    ld bc, $b1e4
    db $e3
    ld bc, $99e4
    db $e3
    ld bc, $b1e4
    db $e3
    ld bc, $79e4
    call c, $e3c3
    inc bc
    ld b, c
    ld hl, $e401
    or c
    db $e3
    ld bc, $b0dc
    inc hl
    call c, Call_000_29c7
    jr nz, jr_01f_4f5a

jr_01f_4f5a:
    call c, $e4b0
    or e
    call c, $bbc7
    call c, Call_01f_55c4
    ld d, c
    ld [hl], c
    ld d, c
    ld b, c
    ld hl, $4145
    ld d, c
    ld b, c
    ld hl, $5101
    ld b, c
    ld hl, $7351
    sub c
    ld d, c
    ld b, c
    ld [hl], e
    ld d, c
    ld b, l
    sub $c2
    ld d, b
    ld [hl], b
    sub b
    or b
    call c, $e3c3
    ld bc, $b1e4
    sub c
    db $e3
    ld bc, $b3e4
    sub e
    ld [hl], c
    and e
    sub c
    ld [hl], e
    ld d, c
    ld b, c
    ret c

    call nz, Call_01f_7393
    ld d, e
    or e
    sub e
    ld [hl], e
    db $e3
    inc bc

jr_01f_4f9c:
    db $e4
    or e
    sub e
    db $e3
    inc hl
    ld b, e
    inc bc
    call c, $2bc7

jr_01f_4fa6:
    inc bc
    call c, $e4b0
    or e
    call c, $bbc7
    call c, $fec3
    nop
    dec d
    ld c, a
    call c, $c113
    db $e4
    nop
    ret nz

    ld b, b
    ret nz

    push hl
    ld [hl], b
    ret nz

    db $e4
    ld b, b
    ret nz

    nop
    ret nz

    ld b, b
    ret nz

    nop
    ret nz

    ld [hl], b
    ret nz

    ld d, b
    ret nz

    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    ld d, b
    ret nz

    sub b
    ret nz

    ld b, b
    ret nz

    sub b
    ret nz

    jr nz, jr_01f_4f9c

    ld d, b
    ret nz

jr_01f_4fde:
    push hl
    sub b
    ret nz

    db $e4
    ld d, b
    ret nz

    jr nz, jr_01f_4fa6

    ld d, b
    ret nz

jr_01f_4fe8:
    ld b, b
    ret nz

    ld d, b
    ret nz

jr_01f_4fec:
    ld b, b
    ret nz

    ld [hl], b
    ret nz

    nop
    ret nz

    ld [hl], b
    ret nz

jr_01f_4ff4:
    ld b, b
    ret nz

    ld [hl], b
    ret nz

jr_01f_4ff8:
    ld b, b
    ret nz

    ld [hl], b
    ret nz

jr_01f_4ffc:
    ld d, b
    ret nz

    sub b
    ret nz

jr_01f_5000:
    nop
    ret nz

    sub b
    ret nz

    ld d, b
    ret nz

jr_01f_5006:
    ld [hl], b
    ret nz

    sub b
    ret nz

jr_01f_500a:
    ld [hl], b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    nop
    ret nz

    ld [hl], b
    ret nz

jr_01f_5014:
    ld b, b
    ret nz

    ld [hl], b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    jr nz, jr_01f_4fde

jr_01f_501e:
    ld d, b
    ret nz

    push hl
    sub b

jr_01f_5022:
    ret nz

    db $e4
    ld d, b
    ret nz

    jr nz, jr_01f_4fe8

    ld d, b
    ret nz

    jr nz, jr_01f_4fec

    ld d, b
    ret nz

    ld [hl], b
    ret nz

    nop
    ret nz

    jr nz, jr_01f_4ff4

    ld [hl], b
    ret nz

jr_01f_5036:
    jr nz, jr_01f_4ff8

    ld [hl], b
    ret nz

    jr nz, jr_01f_4ffc

    ld [hl], b
    ret nz

    jr nz, jr_01f_5000

    push hl
    or b
    ret nz

    db $e4

jr_01f_5044:
    jr nz, jr_01f_5006

    ld [hl], b
    ret nz

    jr nz, jr_01f_500a

    ld [hl], b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld [hl], b
    ret nz

    jr nz, jr_01f_5014

    ld d, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld d, b
    ret nz

    jr nz, jr_01f_501e

    ld d, b
    ret nz

    jr nz, jr_01f_5022

    ld d, b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    nop
    ret nz

    ld [hl], b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    jr nz, jr_01f_5036

    ld d, b
    ret nz

    push hl
    sub b

jr_01f_507a:
    ret nz

    db $e4
    ld d, b
    ret nz

    ld d, b
    ret nz

    ld b, b
    ret nz

    jr nz, jr_01f_5044

    ld d, b
    ret nz

    ld b, b
    ret nz

    nop
    ret nz

    ld [hl], b
    ret nz

    nop
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    ld d, b
    ret nz

    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    ld d, b
    ret nz

    sub b
    ret nz

    sub b
    ret nz

    ld d, b
    ret nz

    ld [hl], b
    ret nz

    and b
    ret nz

    ld b, b
    ret nz

    and b
    ret nz

    ld [hl], b
    ret nz

    and b
    ret nz

    and b
    ret nz

    ld [hl], b
    ret nz

    ld d, b
    ret nz

    jr nz, jr_01f_507a

    ld d, b
    ret nz

    sub b
    ret nz

    ld [hl], b
    ret nz

    ld b, b
    ret nz

    ld [hl], b
    ret nz

    or b
    ret nz

    sub b
    ret nz

    ld d, b
    ret nz

    sub b
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    or b
    ret nz

    sub b
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    sub b
    ret nz

    ld [hl], b
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    ld [hl], b
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    ld [hl], b
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    ld [hl], b
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    ld [hl], b
    ret nz

    or b
    ret nz

    ld [hl], b
    ret nz

    or b
    ret nz

    ld d, b
    ret nz

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld d, b
    ret nz

    cp $00
    or a
    ld c, a
    call c, $fdc1
    ld b, a
    ld d, c
    db $fd
    ld d, h
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld h, d
    ld d, c
    db $fd
    ld d, h
    ld d, c
    db $fd
    ld d, h
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld d, h
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld h, d
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld d, h
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld b, a
    ld d, c
    db $fd
    ld b, a

jr_01f_5142:
    ld d, c
    cp $00
    ld a, [bc]
    ld d, c
    pop bc
    or c
    db $10

jr_01f_514a:
    pop bc
    or c
    db $10
    pop bc
    or c
    db $10
    pop bc
    or c
    db $10
    rst $38
    pop bc
    or c
    db $10
    pop bc
    or c
    db $10
    pop bc
    or c
    db $10
    or c
    db $10
    or c
    db $10
    rst $38
    pop bc
    or c
    db $10
    pop bc
    or c
    db $10
    pop bc
    or c
    db $10
    pop bc
    or b
    db $10
    or b
    db $10
    rst $38
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    db $ec
    inc bc
    add sp, -$16
    ld a, [bc]
    inc d
    call c, $c74d
    xor $ed
    db $e4
    ld h, a
    xor $ff
    call c, $e5b2
    db $fd
    ld c, d
    ld d, d
    cp $03
    adc b
    ld d, c
    ld b, b
    jr nc, jr_01f_5142

    and b
    ld [hl], b
    add b
    ret nz

    and b
    ld b, b
    jr nc, jr_01f_514a

    and b
    ld [hl], b
    add b
    sub b
    and b
    db $fd
    ld c, d
    ld d, d
    cp $04
    sbc a
    ld d, c

Call_01f_51a6:
    db $fd
    ld [hl], l
    ld d, d
    push hl
    ld [hl], b
    ld h, b
    ld b, b
    ld [hl], b
    db $fd
    ld [hl], l
    ld d, d
    push hl
    sub b
    ld [hl], b
    ld b, b
    sub b
    db $fd
    ld [hl], l
    ld d, d
    push hl
    or b
    sub b
    ld [hl], b
    ld h, b
    call c, Call_01f_73c3
    ld h, e
    ld b, e
    inc sp
    call c, $fdc2
    ld h, l
    ld d, d
    push hl
    or d
    db $fd
    ld h, l
    ld d, d
    ld [bc], a
    db $fd
    ld h, l
    ld d, d
    ld [de], a
    call c, $e5c3
    ld [hl], e
    ld h, e
    ld b, e
    inc sp
    ld b, e
    inc sp
    inc bc
    and $b3
    call c, $b0c2
    and b

Jump_01f_51e3:
    ld [hl], b
    and b
    or b
    and b
    ld [hl], b
    and b
    push hl
    nop
    and $b0
    add b
    or b
    push hl
    nop
    and $b0
    add b
    or b
    push hl
    stop
    and $90
    push hl
    nop
    stop
    and $90
    push hl
    nop
    jr nz, @+$12

    and $a0
    push hl
    db $10
    jr nz, jr_01f_521a

    and $a0
    push hl
    db $10
    rst $08
    cp $08
    ld c, $52
    call c, $fdc3
    ld e, e
    ld d, d
    or c
    ld [hl], c

jr_01f_521a:
    push hl
    inc de
    and $71
    sub e
    ld h, c
    db $fd
    ld e, e
    ld d, d
    and c
    ld [hl], c
    or e
    ld [hl], c
    ld h, c
    ld [hl], c
    ld sp, $c2dc
    db $fd
    ld h, l
    ld d, d
    push hl
    or d
    db $fd
    ld h, l
    ld d, d
    ld [bc], a
    db $fd
    ld h, l
    ld d, d
    ld [de], a
    call c, $e5c7
    ld h, a
    scf
    call c, $fdc2
    ld c, d
    ld d, d
    db $fd
    ld c, d
    ld d, d
    cp $00
    add l
    ld d, c
    ld b, b
    jr nc, @-$4e

    and b
    ld [hl], b
    add b
    ret nz

    and b
    ld b, b
    jr nc, @-$4e

    and b
    ld [hl], b
    add b
    ret nz

    and b
    rst $38
    and $71
    and e
    ld [hl], c
    push hl
    inc de
    and $71
    and c
    rst $38
    push hl
    ld b, b
    ld b, b
    ld d, b
    ld b, b
    ld [hl], b
    ld b, b
    sub b
    ld b, b
    and b
    ld b, b
    or b
    ld b, b
    db $e4
    nop
    rst $38
    ld b, b
    ld b, b
    jp Jump_01f_40e7


    jp nz, $c040

    rst $38
    ld [$150b], a
    db $ec
    inc bc
    call c, $e40f
    add a
    call c, $e34d
    daa
    call c, $fdc2
    scf
    ld d, e
    cp $03
    adc l
    ld d, d
    and $40
    ld b, b
    or b
    push hl
    nop
    pop bc
    nop
    and $b0
    ld b, b
    ld b, b
    sub b
    ld [hl], b
    ld d, b
    ld h, b

jr_01f_52a4:
    ld [hl], b
    jr nc, jr_01f_52a4

    scf
    ld d, e
    cp $04
    and [hl]
    ld d, d
    pop bc
    db $fd
    ld c, e
    ld d, e
    push hl
    inc bc
    db $fd
    ld c, e
    ld d, e
    push hl
    inc de
    db $fd
    ld c, e
    ld d, e
    push hl
    inc sp
    call c, $e4d3
    ld b, e
    inc sp
    inc bc
    push hl
    or e
    call c, $fdd2
    ld d, l
    ld d, e
    push hl
    ld h, e
    db $fd
    ld d, l
    ld d, e
    push hl
    ld [hl], e
    db $fd
    ld d, l
    ld d, e
    push hl
    and e
    call c, $e4d3
    ld b, e
    inc sp
    inc bc
    push hl
    or e
    db $e4
    inc bc
    push hl
    or e
    ld [hl], e
    ld h, c
    call c, Call_01f_47d6
    ld d, a
    ld h, a
    ld [hl], a
    call c, $fdd2
    ld e, d
    ld d, e
    ret


    ld b, b
    ret nz

    db $fd
    ld e, d
    ld d, e
    set 7, l
    ld e, d
    ld d, e
    set 7, l
    ld e, d
    ld d, e

Jump_01f_52fd:
    call $d3dc
    db $fd
    ld l, l
    ld d, e
    inc sp
    db $fd
    ld l, l
    ld d, e
    ld sp, $dcc1
    jp nc, $60fd

    ld d, e
    pop bc
    push hl
    ld h, e
    and $40
    ld b, b
    push hl
    or b
    ret nz

    db $e4
    nop
    ret nz

    db $10
    ret nz

    jr nz, jr_01f_532e

    pop bc
    push hl
    ld [hl], e
    db $fd
    ld h, b
    ld d, e
    push hl
    and e
    call c, $b7d6
    db $e4

jr_01f_532a:
    scf
    call c, $fdd2

jr_01f_532e:
    scf
    ld d, e
    db $fd
    scf
    ld d, e
    cp $00
    adc e
    ld d, d
    and $40
    ld b, b
    or b
    push hl
    nop
    pop bc
    nop
    and $b0
    ld b, b
    ld b, b
    or b
    push hl
    nop
    pop bc
    nop
    and $b0
    rst $38
    and $40
    ld b, b
    pop bc
    rst $20
    ld b, b
    jp nz, $c240

    rst $38
    and $40
    ld b, b
    ret


    rst $38
    rst $20
    ld b, b
    ld [hl], b
    ld b, b
    jr nc, @+$01

    and $40
    ld b, b
    db $e4
    ld b, b
    ret nz

    jr nc, @-$3e

    jr nz, jr_01f_532a

    stop
    rst $38
    push hl
    ld b, l
    ld [hl], l
    ld b, e
    sub l
    db $e4
    dec b
    push hl
    or e
    ld [hl], l
    and l
    ld h, e
    ld b, l
    ld h, l
    rst $38
    call c, $ea11
    ld [$cd26], sp
    db $e4
    jr nz, @+$32

    db $fd
    ldh [rHDMA3], a
    db $fd
    ldh [rHDMA3], a
    db $e3
    ld b, c
    jp Jump_01f_40e5


    jp nz, $c040

    db $e4
    ld h, e
    db $fd
    db $f4
    ld d, e
    db $e4
    ld [hl], e
    db $fd
    db $f4
    ld d, e
    db $e4
    sub e
    or e
    and e
    ld [hl], e
    ld h, e
    push bc
    db $fd
    rla
    ld d, h
    or e
    and e
    ld [hl], e
    ld h, e
    ld [hl], e
    ld h, e
    ld b, e
    inc sp
    db $fd
    cp $53
    set 7, l
    cp $53
    set 7, l
    cp $53
    ret


    ld b, b
    ret nz

    db $fd
    cp $53
    set 7, l
    cp $53
    set 7, l
    cp $53
    ret


    jr nz, @+$32

    db $fd
    inc b
    ld d, h
    db $fd
    inc b
    ld d, h
    ld b, c
    jp $17fd


    ld d, h
    or a
    ld h, l
    jr nz, jr_01f_540a

    rst $08
    rst $08
    cp $00
    add l
    ld d, e
    db $e3
    ld b, e
    or e
    and e
    ld [c], a
    inc hl
    inc de
    db $e3
    add e
    ld [hl], e
    or e
    and e
    ld b, e
    inc sp
    sub e
    add e
    ld b, e
    ld h, e
    inc sp
    rst $38
    ld [c], a
    ld b, b
    ld b, b
    jp Jump_01f_40e5


    jp nz, $c040

    rst $38
    push hl
    ld b, b
    ld [hl], b
    ld b, b
    jr nc, @+$01

    ld b, e
    or e
    and e
    db $e4
    inc hl
    inc de

jr_01f_540a:
    push hl
    add e
    ld [hl], e
    or e
    and e
    ld b, e
    inc sp
    sub e
    add e
    ld b, e
    ld h, e
    inc sp
    rst $38
    db $e4
    ld b, b
    jp nz, $c040

    ld h, e
    push bc
    ld b, b
    jp nz, $c040

    ld [hl], e
    push bc
    ld b, b
    jp nz, Jump_01f_4040

    and e
    rst $38
    call c, $b0cd
    inc c
    or b
    inc c
    db $fd
    sub c
    ld d, h
    cp $03
    jr nc, jr_01f_548b

    or e
    dec c
    or e
    inc c
    or e
    dec c
    or c
    inc c
    or c
    inc c
    db $fd
    sub c
    ld d, h
    cp $03
    ld b, c
    ld d, h
    or e
    dec c
    or e
    inc c
    or e
    dec c
    or e
    dec c
    db $fd
    sbc d
    ld d, h
    cp $03
    ld d, b
    ld d, h
    db $fd
    and d
    ld d, h
    db $fd
    sbc d
    ld d, h
    cp $03
    ld e, d
    ld d, h
    db $fd
    and d
    ld d, h
    or e
    add hl, bc
    or e
    ld a, [bc]
    or e
    ld a, [bc]
    pop bc
    or c
    add hl, bc
    or e
    dec c
    rst $08
    cp $0d
    ld l, a
    ld d, h
    set 7, l
    sbc d
    ld d, h
    cp $03
    ld [hl], l
    ld d, h
    or e
    inc c
    or e
    inc c
    or e
    inc c
    pop bc
    or b
    inc c
    or b
    inc c
    db $fd
    sub c
    ld d, h
    db $fd

jr_01f_548b:
    sub c
    ld d, h
    cp $00
    jr nc, jr_01f_54e5

    or e
    dec c
    or e
    inc c
    or e
    dec c
    or e
    inc c
    rst $38
    or b
    inc c
    or b
    inc c
    ret


    or e
    ld c, $ff
    or e
    add hl, bc
    or e
    ld a, [bc]
    or e
    ld a, [bc]
    or e
    dec bc
    rst $38
    db $ed
    nop
    ld a, b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$340c], a
    add sp, -$24
    or l
    push hl
    sub l
    call c, $81b1
    ld h, c
    ld b, c
    ld sp, $3f11
    call c, $e5b5
    inc de
    and $83
    push hl
    ld b, e
    and $b3
    push hl
    sub c
    add a
    call c, $81a7
    sub c
    or c
    call c, $85b5
    ld b, c
    ld h, c
    ld b, c
    ld sp, $dc41
    and a
    ld h, a
    scf
    call c, Call_000_33b5
    and $b3

jr_01f_54e5:
    push hl
    ld h, e
    inc sp
    or c
    sub a
    call c, $e4b7
    ld b, c
    ld sp, $3541
    ld de, $31e5
    ld b, c
    ld h, c
    ld [hl], c
    add c
    call c, $8097
    ld [hl], b
    add b
    ld [hl], b
    add c
    call c, Call_01f_67b7
    call c, $13b5
    and $83
    push hl
    ld b, e
    and $b3
    push hl
    sub c
    add a
    call c, $81b7
    sub c
    or c
    add l
    ld b, c
    ld h, c
    ld b, c
    ld sp, $6741
    call c, Call_000_3397
    inc de
    call c, Call_000_33b5
    and $b3
    push hl
    ld h, e
    inc sp
    or c
    sub a
    call c, Call_01f_61b7
    add c
    sub c
    or e
    sub e
    or c
    sub c
    add c
    ld h, c

jr_01f_5533:
    call c, Call_01f_43c2
    and $b3
    push hl
    ld b, c
    ld b, e
    ld b, e
    call c, $e6b7
    or c
    push hl
    ld de, $3921
    and $b1
    push hl
    ld de, $4731
    call c, $e4b5
    inc sp
    push hl
    or e
    ld h, e
    inc sp
    call c, Call_01f_42b7
    jr nc, jr_01f_5533

    or d
    ld de, $4931
    call c, $e6b7
    or c
    push hl
    ld de, $3921
    and $b1
    push hl
    ld de, $4731
    call c, $e4b5
    inc sp
    push hl
    or e
    ld h, e
    sub e
    call c, $81b7
    add b
    ld [hl], b
    add b
    ld [hl], b
    add b
    ld [hl], b
    add a
    cp $00
    jp nz, $ec54

    ld [bc], a
    ld [$230a], a
    call c, $e4c6
    dec d
    call c, $e5c1
    or c
    sub c
    add c
    ld h, c
    ld b, c
    ld h, c
    db $ec
    inc bc
    or b
    and b
    or b
    and b
    or b
    and b
    or a
    db $ec
    ld [bc], a
    call c, $e5c7
    ld b, e
    and $b3
    push hl
    add e
    ld b, e
    db $e4
    ld de, $bde5
    db $e4
    ld b, l
    ld sp, $e511
    or c
    sub c
    add c
    sbc a
    ld h, e
    inc sp

Call_01f_55b4:
    sub e
    ld h, e
    db $e4
    ld sp, $651d
    ld b, c
    ld sp, $e511
    or c
    and c
    cp a
    ld b, e
    and $b3

Call_01f_55c4:
    push hl
    add e
    ld b, e
    db $e4
    ld de, $bde5
    db $e4
    ld b, l
    ld sp, $e511
    or c
    sub c
    add c
    sbc a
    ld h, e
    inc sp
    sub e
    ld h, e
    db $e4
    ld sp, $651d
    ld b, c
    ld sp, $6141
    add c
    call c, $41c1
    call c, Call_01f_40a1

Call_01f_55e7:
    jr nc, jr_01f_5629

    jr nc, jr_01f_562b

    jr nc, jr_01f_562e

    call c, $e5c7
    or c
    db $e4
    ld de, $3921
    push hl
    or c
    db $e4
    ld de, $4931
    push hl
    or c
    db $e4
    ld de, $dc31
    push bc
    ld h, e
    inc sp
    push hl

jr_01f_5605:
    or e
    db $e4
    sub e
    add d
    sub b
    call c, $81c2
    ld h, c
    ld b, c
    call c, $e5c7
    or c
    db $e4
    ld de, $3921
    push hl
    or c
    db $e4
    ld de, $4931
    push hl
    or c
    db $e4
    ld de, $6331
    inc sp
    sub e
    ld h, e

jr_01f_5626:
    cp a
    cp $00

jr_01f_5629:
    sbc d
    ld d, l

jr_01f_562b:
    call c, $e313

jr_01f_562e:
    db $10
    call nz, Call_01f_60e4
    ret nz

    add b
    ret nz

    sub b
    ret nz

    and b
    ret nz

    and b
    ret nz

    or b
    ret z

    push hl
    or b
    ret nz

    db $e4
    db $10
    ret nz

    jr nc, jr_01f_5605

    db $fd
    cp b
    ld d, [hl]
    db $fd
    call $fd56
    ld [c], a
    ld d, [hl]
    db $fd
    rst $30
    ld d, [hl]
    db $fd
    inc c
    ld d, a
    db $fd
    ld hl, $fd57
    ld [hl], $57
    jr nc, @-$3e

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    sub b
    ret nz

    jr nc, jr_01f_5626

    sub b
    ret nz

    add b
    ret nz

    ld h, b
    ret nz

    db $fd
    cp b
    ld d, [hl]
    db $fd
    call $fd56
    ld [c], a
    ld d, [hl]
    db $fd
    rst $30
    ld d, [hl]
    db $fd
    inc c
    ld d, a
    db $fd
    ld hl, $fd57
    ld [hl], $57
    ld b, b
    jp nz, $b0e5

    jp nz, Jump_01f_40e4

    ret nz

    ld b, b
    jp nz, $c0b0

    db $fd
    inc c
    ld d, a
    db $fd
    cp b
    ld d, [hl]
    db $fd
    ld c, e
    ld d, a
    ld b, b
    ret nz

    add b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    ld b, b

jr_01f_56a1:
    ret nz

    add b
    ret nz

    ld h, b
    ret nz

    ld b, b
    ret nz

    db $fd
    inc c
    ld d, a
    db $fd
    cp b
    ld d, [hl]
    db $fd
    ld c, e
    ld d, a
    db $fd
    call $fe56
    nop
    ld b, l
    ld d, [hl]
    ld b, b

jr_01f_56b9:
    ret nz

    add b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    ld b, b

jr_01f_56c3:
    ret nz

    add b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    rst $38
    ld b, b

jr_01f_56ce:
    ret nz

    add b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    ld b, b

jr_01f_56d8:
    ret nz

    push hl
    or b
    ret nz

    db $e4
    db $10
    ret nz

    jr nc, jr_01f_56a1

    rst $38
    ld b, b

jr_01f_56e3:
    ret nz

    or b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    or b
    ret nz

    ld b, b

jr_01f_56ed:
    ret nz

    or b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    or b

jr_01f_56f5:
    ret nz

    rst $38
    jr nc, jr_01f_56b9

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    sub b
    ret nz

    jr nc, jr_01f_56c3

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    sub b
    ret nz

    rst $38
    jr nc, jr_01f_56ce

    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    jr nc, jr_01f_56d8

    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    rst $38
    jr nc, jr_01f_56e3

    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    jr nc, jr_01f_56ed

    push hl
    or b
    ret nz

    db $e4
    db $10
    ret nz

    jr nc, jr_01f_56f5

    rst $38
    ld h, b
    ret nz

    or b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    or b
    ret nz

    ld h, b
    ret nz

    or b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    or b
    ret nz

    rst $38
    ld h, b
    ret nz

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    sub b
    ret nz

    ld h, b
    ret nz

    sub b
    ret nz

jr_01f_5759:
    push hl
    or b
    ret nz

    db $e4
    sub b
    ret nz

    rst $38
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    ld [$3409], a
    db $ec
    inc bc
    call c, $e6c1
    ld b, b
    ld [hl], b
    or b
    push hl
    jr nz, jr_01f_5759

    ld [hl], e
    ld [hl], l
    ld [hl], b
    ld [hl], b
    ld [hl], e
    ld [hl], e
    ld [hl], e
    ret c

    pop bc
    sub c
    sub c
    sub c
    sub c
    sub c
    ld h, c
    db $fd
    pop hl
    ld d, a
    db $fd
    ld [$fd57], a
    pop hl
    ld d, a
    push hl
    rlca
    ret c

    add $43
    ld b, e
    inc bc
    call c, $e6c6
    or a
    ret c

    rst $20
    push hl
    ld d, e
    ld b, e
    inc bc
    call c, Call_000_29e7
    call c, $e6c6
    or c
    push hl
    ld bc, $fd21
    pop hl
    ld d, a
    db $fd
    ld [$fd57], a
    pop hl
    ld d, a
    dec b
    dec b
    ld b, e
    dec h
    ld d, c
    ld [hl], c
    inc hl
    ld [hl], c
    ld [hl], l
    sub e
    ld d, c
    sub c
    db $e4
    ld bc, $2be5
    ld b, e
    ld d, a
    ld [hl], e
    ld d, e
    ld c, e
    ld d, e
    ld [hl], a
    call c, $e4b6

jr_01f_57c9:
    inc bc
    inc de
    db $fd
    db $fc

jr_01f_57cd:
    ld d, a
    ret c

    or h
    db $e4

jr_01f_57d1:
    inc bc
    inc bc
    inc de
    db $fd

jr_01f_57d5:
    db $fc
    ld d, a
    ret c

    or d
    push hl
    ld b, e
    ld b, e
    inc de
    cp $00
    add d
    ld d, a
    call c, $e5c6
    dec h
    and $b1
    push hl
    daa
    rst $38
    dec b
    ld d, l
    inc bc
    daa
    call c, Call_01f_55e7
    ld b, b
    jr nc, jr_01f_581b

    ret c

    add $03
    and $b3
    push hl
    inc bc
    rst $38
    call c, Call_000_20c1
    ret nz

    and $20
    jr nz, @+$22

    ret nz

    jr nz, jr_01f_5827

    jr nz, jr_01f_57c9

    jr nz, jr_01f_582b

    jr nz, jr_01f_57cd

    jr nz, jr_01f_582f

    jr nz, jr_01f_57d1

    jr nz, jr_01f_5833

    jr nz, jr_01f_57d5

    jr nz, jr_01f_5837

    rst $38
    ld [$4610], a

jr_01f_581b:
    db $ec
    ld bc, $e1dc
    and $70
    or b
    push hl
    jr nz, @+$62

    ld [hl], e
    ld [hl], l

jr_01f_5827:
    ld [hl], b
    ld [hl], b
    ld [hl], e
    ld [hl], e

jr_01f_582b:
    ld [hl], e
    ret c

    pop hl
    ld d, c

jr_01f_582f:
    ld d, c
    ld d, c
    ld d, c
    ld d, c

jr_01f_5833:
    ld h, c
    ld [$4610], a

jr_01f_5837:
    db $fd
    jp nz, $e658

    sub e
    ld d, e
    db $fd
    call z, $e658
    sub a
    cp a
    db $fd
    jp nz, $e658

    sub l
    ld d, c
    ret c

    rst $20
    db $e4
    inc bc
    push hl
    or e
    db $e4
    inc bc
    call c, $27e7
    call c, $e695
    dec h
    jr nz, jr_01f_58ba

    ld a, a
    db $fd
    jp nz, $e658

    sub c
    ld d, l
    db $fd
    call z, $e558
    ld bc, $95e6
    or l
    ld [hl], c
    ld d, a
    db $fd
    jp nz, $d858

    sub l
    and $73
    ld d, h
    sub d
    ret c

jr_01f_5875:
    and $e4
    ld d, e

jr_01f_5878:
    ld b, e
    ld d, e
    call c, Call_01f_75e7
    and c
    ld [hl], a
    ld [$2610], a

jr_01f_5882:
    db $ec
    inc bc
    call c, Call_01f_770b
    call c, $97e7
    db $ec
    ld bc, $e7dc
    and l
    ld d, c

jr_01f_5890:
    ld d, a
    push hl
    daa
    db $e4
    and e
    or e
    db $e3
    dec b
    db $e4
    ld [hl], c
    ld [hl], a
    push hl
    ld b, a
    call c, $e3d7
    inc bc

jr_01f_58a1:
    inc de
    db $fd

jr_01f_58a3:
    sub $58
    jp nz, $c220

    jr nz, jr_01f_5882

jr_01f_58aa:
    push hl
    db $e3
    inc bc
    inc bc
    inc de
    db $fd
    sub $58
    jr nz, jr_01f_5875

    jr nz, jr_01f_5878

    jr nz, jr_01f_5890

    db $e3
    db $e3

jr_01f_58ba:
    inc bc
    inc bc
    db $e4
    or e
    cp $00
    inc [hl]
    ld e, b
    call c, $e5e7
    ld [hl], l
    or c
    db $e4
    daa
    call c, $ff95
    call c, $e4e7
    ld d, l
    ld b, b
    jr nc, jr_01f_58fa

    call c, $ff95
    call c, $20e1
    pop bc
    db $e4
    jr nz, @-$3c

    jr nz, jr_01f_58a1

    jr nz, jr_01f_58a3

    jr nz, @+$01

    call c, $e510
    ld [hl], b
    ret nz

    jr nz, jr_01f_58aa

    ld [hl], b
    jp nz, $c470

    ld [hl], b
    ld [hl], b
    ld [hl], b
    jp nz, $c270

    ld [hl], b
    jp nz, Jump_000_10d8

    ld d, c
    ld d, c

jr_01f_58fa:
    ld d, c
    ld d, c
    ld d, c
    sub c
    db $fd
    ld l, c
    ld e, c
    db $fd
    ld [hl], b
    ld e, c
    db $fd
    ld l, c
    ld e, c
    db $fd
    ld l, c
    ld e, c
    db $fd
    ld l, c
    ld e, c
    db $fd
    ld [hl], b
    ld e, c
    cp $03
    inc b
    ld e, c
    db $fd
    ld l, c
    ld e, c
    ld [hl], l
    ld [hl+], a
    sub l
    ld d, d
    sub d
    ld d, d
    db $fd
    ld [hl], a
    ld e, c
    and d
    ld d, d
    db $fd
    ld [hl], a
    ld e, c
    or d
    ld [hl], d
    db $fd
    ld a, h
    ld e, c
    db $e4
    ld [bc], a
    push hl
    ld [hl], d
    db $fd
    ld a, h
    ld e, c
    db $e4
    ld [de], a
    push hl
    sub d
    db $fd
    add l
    ld e, c
    db $e3
    db $eb
    nop
    ld b, d
    inc hl
    jp $ebe2


    nop
    ld [hl-], a
    inc hl
    db $e3
    db $eb
    nop
    ld b, d
    inc hl
    pop bc
    ret c

    db $10
    db $e4
    inc bc
    inc bc

jr_01f_594e:
    inc de
    db $fd
    add l
    ld e, c
    ld [c], a
    db $eb
    nop
    ld [hl-], a
    inc hl
    jp $ebe3


    nop
    ld b, d
    inc hl
    push bc
    ret c

    db $10
    db $e4
    inc bc
    inc bc
    push hl
    or e
    cp $00
    cp $58
    ld [hl], l
    ld [hl+], a
    ld [hl], l
    ld [hl+], a
    ld [hl], d
    ld [hl+], a
    rst $38
    ld d, l
    ld [bc], a
    ld d, l
    ld [bc], a
    ld d, d
    ld [bc], a
    rst $38
    and l
    ld d, d
    and l
    ld d, d
    rst $38
    db $e4
    dec b
    push hl
    ld [hl], d
    db $e4
    dec b
    push hl
    ld [hl], d
    rst $38
    call c, $e410
    jr nz, jr_01f_594e

    rst $38
    sub $c3
    or b
    inc bc
    or b
    inc bc
    or b
    inc b
    or b
    inc b
    call c, Call_000_02b0
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    ld [bc], a
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    jp nz, Jump_000_02b0

    jp nz, $b1d8

    inc bc
    or c
    inc b
    or c
    ld [bc], a
    or c
    inc bc
    or c
    ld [bc], a
    or c
    ld bc, $b0dc
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    ld [bc], a
    or b
    inc bc
    jp nz, $d4fd

    ld e, d
    db $fd
    call nc, $b05a
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    ld [bc], a
    or b
    inc bc
    ret nz

    or b
    inc bc
    or b
    ld [bc], a
    db $fd
    ld [c], a
    ld e, d
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    inc bc
    or b
    ld [bc], a
    ret nz

    or b
    ld [bc], a
    ret nz

    db $fd
    ld [c], a
    ld e, d
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    inc bc
    or b
    ld [bc], a
    ret nz

    sub $b0
    inc bc
    or b
    inc bc
    or b
    inc b
    or b
    inc b
    call c, $d4fd
    ld e, d
    db $fd
    ld [c], a
    ld e, d
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    inc bc
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    jp nz, Jump_000_02b0

    call nz, $03b0
    or b
    ld [bc], a
    or b
    ld [bc], a
    ret nz

    or b
    inc bc
    or b
    ld [bc], a
    db $fd
    call nc, $fd5a
    ld [c], a
    ld e, d
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, $03b0
    or b
    ld [bc], a
    or b
    ld [bc], a
    ret nz

    or b
    inc b
    or b
    inc bc
    or b
    ld [bc], a
    jp nz, $03b0

    call nz, Call_000_02b0
    or b
    inc b
    or b
    ld [bc], a
    ret nz

    sub $b0
    inc bc
    or b
    inc bc
    or b
    inc b
    or b
    inc b
    call c, $01b0
    jp nz, Jump_000_02b0

    call nz, $03b0
    or b
    ld [bc], a
    or b
    ld bc, $b0c2
    ld [bc], a
    jp nz, $03b0

    call nz, $03b0
    or b
    ld [bc], a
    or b
    inc bc
    jp nz, Jump_000_02b0

    jp nz, $03b0

    call nz, Call_000_02b0
    or b
    inc bc
    or b
    inc b
    ret nz

    or b
    inc bc
    or b
    ld [bc], a
    or b
    ld [bc], a
    jp nz, $03b0

    call nz, Call_000_02b0
    or b
    inc bc
    or b
    ld [bc], a
    jp nz, $05b0

    call nz, Call_000_02b0
    jp nz, $03b0

    or b
    ld [bc], a
    or b
    ld bc, $b0c4
    ld [bc], a
    or b
    inc bc
    or b
    ld [bc], a
    ret nz

    or b
    ld bc, $d8c0
    or e
    ld [bc], a
    or e
    inc bc
    or e
    ld bc, $b0dc
    dec b
    call nz, Call_000_02b0
    jp nz, $03b0

    or b
    ld [bc], a
    or b
    inc bc
    call nz, Call_000_02b0
    or b
    inc bc
    or b
    ld bc, $b0c0
    inc bc
    or b
    ld [bc], a
    ret c

    or e
    ld [bc], a
    or e
    inc bc
    or e
    ld [bc], a
    cp $00
    or [hl]
    ld e, c
    or b
    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, Call_000_02b0
    or b
    inc bc
    or b
    ld [bc], a
    jp nz, $b0ff

    ld [bc], a
    jp nz, Jump_000_02b0

    call nz, $03b0
    or b
    ld [bc], a
    or b
    ld [bc], a
    jp nz, $f8ff

    db $ed
    ld bc, $f000
    ld [hl], a
    ld [$2606], a
    db $ec
    ld [bc], a
    add sp, -$2c
    or c
    push hl
    add c
    add c
    add c
    call c, $e4b3
    ld b, e
    rst $38
    ld hl, sp-$16
    ld [$ec27], sp
    ld [bc], a
    call nc, $e4c1
    ld b, c
    ld b, c
    ld b, c
    call c, $b3c3
    rst $38
    ld hl, sp-$2c
    db $10
    db $e4
    or b
    ret nz

    or b
    ret nz

    or b
    ret nz

    call c, $e410
    or c
    pop bc
    rst $38
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    db $ec
    inc bc
    add sp, -$16
    ld a, [bc]
    inc d
    call c, $e4b2
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    and e
    and e
    and e
    and e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    db $e3
    inc de
    inc de
    inc de
    inc de
    push hl
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    and e
    and e
    and e
    and e
    and $71
    and e
    ld [hl], c
    push hl
    inc de
    and $71
    and c
    or c
    ld [hl], c
    push hl
    inc de
    and $71
    sub e
    ld h, c
    cp $02
    ld [hl-], a
    ld e, e
    call c, $e51f
    ld c, a
    rrca
    cpl
    and $af
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    cp $00
    ld [hl-], a
    ld e, e
    ld [$150b], a
    db $ec
    inc bc
    call c, $e5c2
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    inc bc
    inc bc
    inc bc
    inc bc
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    inc bc
    inc bc
    inc bc
    inc bc
    or e
    or e
    or e
    or e
    db $e4
    ld h, e
    ld h, e
    ld h, e
    ld h, e
    inc hl
    inc hl
    inc hl
    inc hl
    ld [hl], e
    ld [hl], e
    ld [hl], e
    ld h, e
    cp $02
    ld a, e
    ld e, e
    push hl
    ld b, c
    ld [hl], c
    ld b, c
    ld sp, $4141
    db $e3
    ld b, c
    pop bc
    ld sp, $21c1
    pop bc
    ld de, $e401
    ld b, c
    ld [hl], c
    push hl
    and c
    ld de, $91a1
    and c
    ld [hl], c
    db $e3
    ld [hl], c
    pop bc
    ld h, c
    pop bc
    ld d, c
    pop bc
    ld b, c
    ld sp, $1121
    rst $08
    rst $08
    rst $08
    rst $08
    call c, $ecc7
    ld bc, $4fe4
    cpl
    rrca
    cpl
    cp $00
    ld a, e
    ld e, e
    call c, $ea13
    ld [$fd26], sp
    ld [hl], c
    ld e, h
    cp $10
    ldh [$5b], a
    ld b, e
    jp Jump_01f_43c3


    inc bc
    jp Jump_000_03c3


    inc hl
    jp $23c3


    push hl
    and e
    jp $a3c3


    db $e3
    ld b, c
    pop bc
    or c
    pop bc
    and c
    pop bc
    ld [c], a
    ld hl, $11c1
    pop bc
    db $e3
    add c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    and c
    pop bc
    ld b, c
    pop bc
    ld sp, $91c1
    pop bc
    add c
    pop bc
    ld b, c
    pop bc
    ld h, c
    pop bc
    ld sp, $fec1
    inc bc
    ld hl, sp+$5b
    db $e4
    ld b, e
    or e
    and e
    db $e3
    inc hl
    inc de
    db $e4
    add e
    ld [hl], e
    or e
    and e
    ld b, e
    inc sp
    sub e
    add e
    ld b, e
    ld h, e
    inc sp
    push hl
    ld c, a
    rrca
    cpl
    and $af
    push hl
    ld c, a
    ld e, a
    ld a, a
    push hl
    cp a
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    db $fd
    ld [hl], c
    ld e, h
    cp $00
    ldh [$5b], a
    and $71
    and e
    ld [hl], c
    push hl
    inc de
    and $71
    sub c
    and c
    ld [hl], c
    push hl
    inc de
    and $71
    and c
    ld [hl], c
    pop bc
    rst $38
    db $e4
    ld b, c
    jp Jump_01f_40e5


    jp nz, $c040

    db $e4
    ld h, e
    rst $38
    call c, Call_000_0cb3
    or e
    dec c
    or e
    inc c
    or e
    ld a, [bc]
    or e
    inc c
    or e
    dec c
    or e
    dec bc
    or e
    add hl, bc
    cp $00
    ld a, l
    ld e, h
    db $ed
    nop
    and b
    ldh a, [rPCM34]
    db $ec
    inc bc
    add sp, -$16
    ld [$dc14], sp
    jp Jump_01f_52fd


    ld e, l
    cp $03
    sbc [hl]
    ld e, h
    and $b1
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $3171
    ld b, c
    db $fd
    ld h, c
    ld e, l
    cp $04
    or c
    ld e, h
    db $fd
    ld d, d
    ld e, l
    cp $04
    cp b
    ld e, h
    db $e4
    ld d, c
    ld d, c
    pop bc
    ld d, c
    ld b, c
    ld b, c
    ld sp, $c131
    ld sp, $2121
    db $fd
    sbc h
    ld e, l
    db $e4
    ld hl, $c121
    ld hl, $3131
    ld b, c
    ld b, c
    pop bc
    ld b, c
    ld d, c
    ld d, c
    db $fd
    ld l, [hl]
    ld e, l
    cp $04
    call c, $fd5c
    ld a, l
    ld e, l
    cp $03
    db $e3
    ld e, h
    push hl
    ld de, $91e6
    ld d, c
    push hl
    ld de, $91e6
    ld d, c
    push hl
    sub c
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    sub c
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    db $e4
    ld de, $91e5
    ld d, c
    add c
    ld b, c
    db $e4
    ld bc, $81e5
    ld b, c
    db $e4
    ld bc, $8afd
    ld e, l
    db $fd
    adc d
    ld e, l
    push hl
    add c
    ld b, c
    db $e4
    ld bc, $81e5
    ld b, c
    db $e4
    ld bc, $81e5
    ld b, c
    rst $08
    rst $00
    db $fd
    sub a
    ld e, l
    db $fd
    sub a
    ld e, l
    db $fd
    sub a
    ld e, l
    db $fd
    sub a
    ld e, l
    ld sp, $cfcf
    cp $00
    sbc h
    ld e, h
    and $b1
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $41ff
    add c
    db $e4
    ld bc, $41e5
    add c
    db $e4
    ld bc, $41e5
    add c
    rst $38
    push hl
    ld sp, $b1e6
    push hl
    ld [hl], c
    ld sp, $b1e6
    push hl
    ld [hl], c
    ld sp, $b1e6
    rst $38
    sub c
    ld d, c
    push hl
    ld de, $91e6
    ld d, c
    push hl
    ld de, $91e6
    ld d, c
    rst $38
    push hl
    add c
    ld b, c
    add c
    ld b, c
    db $e4
    ld bc, $81e5
    ld b, c
    db $e4
    ld bc, $31ff
    ld [hl], c
    ld sp, $ff15
    db $ed
    nop
    xor b
    rst $20
    and b
    or b
    and $00
    db $10
    jr nz, jr_01f_5dd7

    ld b, b
    ld d, b
    db $ed
    nop
    or b
    rst $20
    and b
    or b
    and $00
    db $10
    jr nz, jr_01f_5de4

    ld b, b
    ld d, b
    db $ed
    nop
    cp b
    rst $20
    and b
    or b
    and $00
    db $10
    jr nz, jr_01f_5df1

    ld b, b
    ld d, b
    db $ed
    nop
    ret nz

    rst $20
    sub b
    and b
    or b
    and $00
    db $10
    jr nz, jr_01f_5dff

    ld b, b
    db $ed
    nop
    ret z

    rst $20
    add b
    sub b
    and b

jr_01f_5dd7:
    or b

jr_01f_5dd8:
    and $00
    db $10
    jr nz, jr_01f_5e0d

    db $ed
    nop
    ret nc

    rst $20
    ld [hl], b
    add b
    sub b

jr_01f_5de4:
    and b
    or b
    and $00
    db $10
    jr nz, jr_01f_5dd8

    nop
    ret c

    rst $20
    ld h, b
    ld [hl], b
    add b

jr_01f_5df1:
    sub b
    and b
    or b
    and $00
    db $10
    db $ed
    nop
    ldh [$e7], a
    ld d, b
    ld h, b
    ld [hl], b
    add b

jr_01f_5dff:
    sub b
    and b
    or b
    and $00
    db $ed
    nop
    and b
    rst $38
    ld [$150b], a
    db $ec
    inc bc

jr_01f_5e0d:
    call c, $e4d3
    dec [hl]
    dec d
    push hl
    or c
    db $e4
    ld de, $7131
    ld sp, $e515
    or c
    db $e4
    ld de, $7131
    ld sp, $e515
    or c
    and c
    or l
    db $e4
    rla
    pop bc
    add l
    ld h, l
    ld b, c
    ld h, c
    add c
    db $e3
    ld bc, $81e4
    ld h, l
    ld b, c
    ld h, c
    add c
    db $e3
    ld bc, $81e4
    ld h, l
    ld b, c
    ld sp, $6545
    ld b, e
    dec [hl]
    dec d
    push hl
    or c
    db $e4
    ld de, $7131
    ld sp, $e515
    or c
    db $e4
    ld de, $7131
    ld sp, $e515
    or c
    and c
    or l
    db $e4
    rla
    pop bc
    add c
    add c
    pop bc
    add c
    sub c
    sub c
    and c
    and c
    pop bc
    and c
    or c
    or c
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    db $e4
    or c
    or c
    pop bc
    or c
    and c
    and c
    sub c
    sub c
    pop bc
    sub c
    add c
    add c
    rla
    pop bc
    push hl
    or l
    and c
    or c
    db $e4
    ld sp, $3171
    dec d
    push hl
    or c
    db $e4
    ld de, $7131
    ld sp, $e515
    or c
    db $e4
    ld de, $7535
    push hl
    ld [hl], a
    pop bc
    ld d, l
    ld b, c
    ld d, c
    sub c
    db $e4
    ld de, $91e5
    ld [hl], l
    ld d, c
    ld [hl], c
    sub c
    db $e4
    ld de, $91e5
    ld [hl], l
    sub l
    db $e4
    dec d
    ld [hl], a
    pop bc
    ld d, l
    ld b, c
    ld d, c
    sub c
    db $e3
    ld de, $91e4
    ld [hl], l
    sub c
    db $e3
    ld de, $91e4
    ld [hl], l
    sub l
    db $e3
    dec d
    db $e4
    ld h, a
    pop bc
    ld b, l
    ld sp, $8141
    db $e3
    ld bc, $81e4
    ld h, l
    ld b, c
    ld h, c
    add c
    db $e3
    ld bc, $81e4
    ld h, l
    add l
    db $e3
    dec b
    push hl
    ld sp, $3171
    dec d
    ld sp, $3171
    dec d
    and $41
    add c
    push hl
    ld bc, $8141
    db $e4
    ld bc, $8141
    ld bc, $8141
    ld bc, $8141
    ld bc, $8141
    ld bc, $8141
    ld bc, $8141
    ld bc, $e631
    or c
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $b1e6
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $e671
    or c
    push hl
    ld sp, $00fe
    dec c
    ld e, [hl]
    call c, $cf12
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    set 2, [hl]
    db $10
    push hl
    or b
    db $e4
    nop
    db $10
    jr nz, jr_01f_5f61

    ld b, b
    pop bc
    nop
    db $10
    jr nz, jr_01f_5f67

    ld b, b
    ld d, b
    rst $08
    rst $08
    ret


    db $e3
    ld b, a
    db $e4
    or a
    db $e3
    scf
    db $e4
    and a
    db $e3
    daa
    db $e4
    sub a
    db $e3
    rla
    db $e4
    add a
    db $e3
    rlca
    db $e4
    ld [hl], a
    or a
    ld h, a
    and a
    ld d, a
    sub a
    ld b, a
    rst $08
    rst $08
    rst $00
    ld d, b
    ld b, b
    jr nc, jr_01f_5f7d

    stop
    pop bc

Call_01f_5f60:
    ld b, b

jr_01f_5f61:
    jr nc, jr_01f_5f83

    stop
    push hl
    or b

jr_01f_5f67:
    ret


    rst $08
    call c, $cf10
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08

jr_01f_5f7d:
    rst $08
    rst $08
    ret


    cp $00
    ld a, [de]

jr_01f_5f83:
    ld e, a
    call c, $cfcf
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    ret


    rst $38
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    ld [$250b], a
    db $ec
    ld [bc], a
    call c, $e362
    ld b, b
    ld b, b
    db $e4
    or b
    or b
    nop
    pop bc
    db $e3
    or c
    ld b, c
    db $e4
    ld bc, $41b1
    nop
    db $e3
    or b
    pop bc
    cp $0e
    cp c
    ld e, a
    call c, $cfa5
    rst $08
    adc $e4
    nop
    db $e3
    or b
    or c
    cp $00
    cp c
    ld e, a
    db $ec
    ld [bc], a
    add sp, -$16
    ld a, [bc]
    inc h
    call c, $cfc2
    rst $08
    cp $04
    add sp, $5f
    call c, $fdc2
    inc c
    ld h, b
    cp $03
    ldh a, [$5f]
    push hl
    ld b, e
    inc sp
    or e
    and e
    ld [hl], e
    add e
    jp Jump_01f_43a3


    inc sp
    or e
    and e
    ld [hl], e
    add e
    ld [hl], e
    inc sp
    cp $00
    xor $5f
    push hl
    ld b, e
    inc sp
    or e
    and e
    ld [hl], e
    add e
    sub e
    and e
    ld b, e
    inc sp
    or e
    and e
    ld [hl], e
    add e
    jp $ffa3


    call c, $e611
    or c
    pop bc
    push hl
    ld b, c
    pop bc
    ld b, c
    pop bc
    ld b, c
    pop bc
    ld b, c
    pop bc
    ld b, c
    pop bc
    ld b, c
    pop bc
    ld b, c
    pop bc
    ld bc, $e5c1
    ld sp, $31c1
    pop bc
    ld sp, $31c1
    pop bc
    ld sp, $31c1
    pop bc
    ld sp, $fec1
    ld [$6020], sp
    ld c, a
    ccf
    ld a, a
    add a
    scf
    cp $00
    jr nz, jr_01f_60b0

    sub $cf
    rst $08
    rst $08
    rst $08
    or c
    inc c
    or c
    inc c
    or e
    dec c
    or c
    inc c
    or c
    inc c
    or e
    dec c
    or c
    inc c
    or c
    inc c
    or e
    dec c
    or c
    inc c
    or c
    inc c
    or e
    ld c, $b1
    inc c
    or c
    inc c
    pop bc
    ret


    rst $00
    or a
    ld c, $fe
    nop
    ld d, l
    ld h, b
    ld hl, sp-$13
    ld bc, $f000
    ld [hl], a
    db $ec
    ld [bc], a
    push de
    or c
    push hl
    sub c
    sub c
    ld [hl], c
    ld [hl], c
    ld d, c
    ld b, c
    ld d, c
    sub c
    db $e4
    inc bc
    ld b, e
    push hl
    ld d, e
    rst $38
    ld hl, sp-$14
    ld [bc], a
    push de
    jp nz, Jump_01f_51e3

    ld b, b
    ret nz

    ld hl, $c000
    db $e4
    and c
    db $e3
    ld bc, $4121
    ld d, e
    ld [hl], e
    ld d, e
    rst $38
    ld hl, sp-$2b
    db $10
    db $e3
    nop
    ret nz

    db $e4

jr_01f_60b0:
    ld d, c
    db $e3
    nop
    ret nz

    db $e4
    and b
    ret nz

    sub b
    ret nz

    ld [hl], b
    ret nz

    ld d, b
    ret nz

    ld b, b
    ret nz

    db $e3
    ld d, b
    jp nz, $c200

    db $e4
    ld d, c
    pop bc
    rst $38

jr_01f_60c8:
    ld hl, sp-$13

jr_01f_60ca:
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

Call_01f_60e4:
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
    db $e3
    ld d, e
    inc sp
    rlca
    jr nc, jr_01f_60c8

    jr nc, jr_01f_60ca

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
    ld [bc], a
    add sp, -$2b
    and h
    push hl
    and e
    push de
    or c
    db $e4
    ld bc, $0000
    push de
    and h
    inc sp
    push de
    or c
    ld d, c
    ld d, b
    ld d, b
    push de
    or h
    and a
    rst $38
    ld hl, sp-$16
    inc b
    inc hl
    db $ec
    ld [bc], a
    push de
    pop de
    db $e4
    ld [hl], c
    ld [hl], b
    ld [hl], b
    push de
    call nz, $d533
    pop de
    add c
    add b
    add b
    and c
    and b
    and b
    push de
    call nz, $37e3
    rst $38
    ld hl, sp-$2b
    db $10
    db $e4
    inc sp
    add e
    ld [hl], e
    ld d, e
    scf
    rst $38
    db $ed
    nop
    adc h
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$1210], a
    add sp, -$24
    or e
    and $b0
    push hl
    db $10
    jr nz, @+$42

    ld h, b
    add b
    sub b
    or b
    db $e4
    inc de
    push hl
    or c
    db $e4
    ld de, $93e5
    add c
    sub c
    or b
    jp nz, $8095

    or b
    db $e4
    inc de
    push hl
    sub e
    add c
    sub c
    ld h, e
    ld b, c
    ld h, c
    add b
    jp nz, Jump_01f_4367

jr_01f_618c:
    sub l
    ld b, b
    sub b
    db $e4
    daa
    dec d
    push hl
    sub b
    db $e4
    db $10
    ld b, a
    inc hl
    inc de
    push hl
    or e
    sub e
    add b
    jp nz, $6343

    add e
    cp $00
    ld [hl], b
    ld h, c
    db $ec
    inc bc
    ld [$250a], a

jr_01f_61aa:
    call c, $e5c4
    add b
    sub b
    or b
    db $e4
    db $10
    jr nz, @+$42

    ld h, b
    add b
    sub l

Call_01f_61b7:
    add b
    ld h, b
    ld b, l
    jr nc, jr_01f_61fc

    ld h, b
    jp nz, Jump_01f_4347

    ld h, l
    ld b, b
    jr nz, jr_01f_61d9

    push hl
    or b
    db $e4
    db $10
    jr nz, jr_01f_618c

    rla
    inc de
    dec h
    push hl
    sub b
    db $e4
    jr nz, @+$69

    ld b, l
    db $10
    ld b, b
    sub a
    add e
    sub c
    add c

jr_01f_61d9:
    ld h, e
    add c
    ld h, c
    ld b, b
    ret nz

    push hl
    add b
    ret nz

    sub b
    ret nz

    or b
    ret nz

    db $e4
    db $10
    ret nz

    jr nz, jr_01f_61aa

    ld b, b
    ret nz

    ld h, b
    ret nz

    cp $00
    or [hl]
    ld h, c

jr_01f_61f2:
    call c, $c111
    db $e4
    add b
    ret nz

    ld h, b
    ret nz

jr_01f_61fa:
    ld b, b
    ret nz

jr_01f_61fc:
    db $10
    ret nz

    sub b
    jp nz, $c290

    sub b
    ret nz

    ld b, b
    ret nz

    sub b
    ret nz

    db $10
    ret nz

    sub b
    jp nz, $c290

    sub b
    ret nz

    ld b, b
    ret nz

jr_01f_6212:
    sub b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld h, b
    jp nz, $c260

    ld h, b
    ret nz

    db $10
    ret nz

    ld h, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld h, b
    jp nz, $c260

    ld h, b
    ret nz

    db $10
    ret nz

    ld h, b
    ret nz

    jr nz, jr_01f_61f2

    ld h, b
    jp nz, $c260

    ld h, b
    ret nz

    jr nz, jr_01f_61fa

    ld h, b
    ret nz

    ld b, b
    ret nz

    sub b
    jp nz, $c290

    sub b
    ret nz

    ld b, b
    ret nz

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    jp nz, $c080

    jr nz, jr_01f_6212

    ld h, b
    jp nz, $c060

    ld b, b
    call nz, $c280
    ld h, b
    jp nz, $c040

    db $10
    ret nz

    sub b
    ret nz

    db $10
    ret nz

    sub b
    ret nz

    db $10
    ret nz

    sub b
    ret nz

    ld b, b
    ret nz

jr_01f_626c:
    sub b
    ret nz

    db $10
    ret nz

jr_01f_6270:
    sub b
    ret nz

    db $10
    ret nz

jr_01f_6274:
    sub b
    ret nz

    db $10
    ret nz

jr_01f_6278:
    sub b
    ret nz

    db $10
    ret nz

    sub b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld h, b
    ret nz

    db $10
    ret nz

    ld h, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4

jr_01f_6298:
    ld h, b
    ret nz

    push hl
    sub b

jr_01f_629c:
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld h, b
    ret nz

    db $10
    ret nz

    ld h, b
    ret nz

    jr nz, jr_01f_626c

    ld h, b
    ret nz

    jr nz, jr_01f_6270

    ld h, b

Call_01f_62b1:
    ret nz

    jr nz, jr_01f_6274

    ld h, b
    ret nz

    jr nz, jr_01f_6278

    ld h, b
    ret nz

    ld b, b
    ret nz

    sub b
    ret nz

    ld b, b
    ret nz

    sub b

Call_01f_62c1:
    ret nz

    ld b, b
    ret nz

    sub b
    ret nz

    ld b, b
    ret nz

    sub b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    jr nz, jr_01f_6298

    ld h, b
    ret nz

    jr nz, jr_01f_629c

    ld h, b
    ret nz

    ld b, b
    jp nz, $c280

    ld h, b
    jp nz, $c240

    cp $00
    db $fc
    ld h, c
    db $ed
    nop
    sbc b
    ldh a, [rPCM34]
    db $ec
    inc bc
    add sp, -$16
    inc c
    inc hl
    call c, $c380
    db $e4
    cp e
    call c, $e4b4
    ld [hl], b
    add $70
    add $e5
    or b
    add $b0
    jp nz, $c2b0

    or b
    add $b0
    add $b0
    add $e4
    ld h, b
    add $00
    push hl

jr_01f_6313:
    or b
    ld [hl], b

jr_01f_6315:
    call nz, $c640
    ld b, b
    add $60
    add $40
    add $70
    add $70
    add $60
    add $60
    add $70
    add $40
    add $20
    add $40
    add $70
    add $70
    add $60
    add $b0
    add $b0
    add $e4
    nop
    add $00
    add $10
    add $10
    add $00
    add $00
    jp nz, $84dc

    nop
    jp nz, $b4dc

    jr nz, jr_01f_6313

    jr nz, jr_01f_6315

    push hl
    sub b
    add $90
    add $dc
    and a
    or a
    or a
    db $e4
    rlca
    rlca
    rla
    rla
    call c, $2fa6
    rst $08
    rst $08
    rst $08
    rst $08
    call c, $b392
    db $e3
    ld b, e
    inc hl
    inc bc
    db $e4
    or e
    db $e3
    ld b, e
    inc hl
    inc bc
    db $e4
    or e
    db $e3
    ld b, e
    inc hl
    inc bc

jr_01f_6377:
    db $e4
    or e
    ld [hl], e
    ld h, e
    ld b, e
    db $e3
    rrca
    rrca
    cp $00
    ld a, [$ea62]
    inc d
    inc [hl]
    db $ec
    inc bc
    call c, $e3a0
    dec bc
    db $e4
    ld b, e
    call c, $e3c1
    rlca
    db $e4
    or e
    call c, Call_01f_70c4
    ld h, b
    ld b, b
    jr nc, jr_01f_6377

    or b
    ld [hl], a
    db $e3
    rlca
    db $e4
    or e
    ld [hl], e
    ld b, e
    ld [hl], e
    db $e3
    rlca
    call c, Call_000_07b7
    call c, $e4c2
    ld [hl], b
    ld h, b
    ld b, b
    ret nz

    call c, $e596
    ld [hl], e
    call c, Call_01f_73c7
    or e
    ld [hl], e
    or e
    db $e4
    inc bc
    push hl
    or e
    call c, $e4b0
    rrca
    ld b, a
    call c, $4bb7
    call c, $e3c5
    inc bc
    db $e4
    or e
    ld [hl], e
    or e
    ld [hl], e
    ld h, e
    ld b, e
    call c, $6bb0
    ld [hl], e
    call c, $67b0
    call c, Call_01f_67b7
    call c, $b3b0
    ld [hl], e
    ld h, e
    ld b, e
    cp a
    call c, $e3b0
    inc bc
    db $e4
    ld [hl], e
    ld h, e
    ld b, e
    call c, $e390
    rrca
    call c, $23b0
    db $e4
    sub e
    add e
    ld h, e
    call c, $e32f
    cpl
    call c, Call_01f_43c0
    db $e4
    or e
    sub e
    ld [hl], e
    db $e3
    ld d, e
    inc bc
    db $e4
    and e
    add e
    db $e3
    ld h, e
    inc hl
    inc bc
    db $e4
    and e
    add e
    ld h, e
    ld b, e
    inc hl
    call c, Call_000_07b0
    call c, Call_000_0790
    call c, $0780
    call c, $0770
    call c, Call_000_0760
    call c, Call_000_0767
    rst $08
    call c, $e3a0
    ld a, a
    ld [c], a
    rrca
    db $e3
    or a
    ld [hl], a
    ld b, a
    ld [hl], a
    ld [c], a
    rrca
    ld [$3400], a
    call c, Call_000_0fa7
    cp $00
    adc [hl]
    ld h, e
    ld [$1104], a

jr_01f_643d:
    call c, $c713
    db $e3
    ld [hl], a
    ld b, b
    add $40
    add $40
    add $40
    jp nz, Jump_000_3040

    ld h, b
    jr nc, jr_01f_648f

    add $70
    add $40
    add $b0
    add $40
    jr nc, jr_01f_643d

    or b

jr_01f_645a:
    call nz, $c6b0
    or b
    add $b0
    add $e3
    nop
    add $00
    add $00
    add $00
    add $e4
    or b
    add $b0
    add $b0
    add $b0
    add $e3
    nop
    add $00
    add $00
    add $00
    add $40
    add $40
    add $40
    add $40
    add $40
    add $40
    add $40
    add $40
    jp nz, $c270

    ld h, b

jr_01f_648f:
    add $60
    add $20
    add $20
    jp nz, $c020

    jr nc, jr_01f_645a

    ld b, b

jr_01f_649b:
    add $40
    add $50

jr_01f_649f:
    add $50
    add $60
    add $60
    add $70
    adc $dc
    dec d
    db $e4
    ld h, b
    jp nz, $c260

    ld [hl], b
    jp nz, $c260

    ld h, b
    adc $60
    jp nz, $c260

    ld [hl], b
    jp nz, $c260

    ld h, b
    add $dc
    inc de
    ld [c], a
    ld b, b
    ret nz

    jr nc, @-$3e

    ld h, b
    ret nz

    jr nc, @-$3e

    ld b, b
    adc $40
    adc $40
    adc $40
    adc $40
    adc $40
    add $e3
    ld b, b
    ret nz

    jr nc, jr_01f_649b

    ld h, b
    ret nz

    jr nc, jr_01f_649f

    cp $00
    ld b, d
    ld h, h
    db $ed
    nop
    and b
    ldh a, [rPCM34]
    db $ec
    inc bc
    add sp, -$16
    ld [$d622], sp
    or e
    and $40
    ld h, b
    add b
    and b
    push hl
    nop
    sub $a0
    dec bc
    sub $b3
    ld bc, $b0e6
    and b
    add b
    ld h, b
    ld b, b
    ld b, c
    pop bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    pop bc
    ld [hl], c
    pop bc
    or c
    push bc
    or c
    push bc
    and c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    pop bc
    push hl
    ld bc, $01c1
    push bc
    ld bc, $01c5
    push bc
    ld bc, $e6c5
    and c
    push bc
    or c
    pop bc
    ld [hl], c
    ret


    ld b, b
    ld h, b
    add b
    sub b
    sub $a0
    cp e
    sub $b3
    or b
    sub b
    ld [hl], b
    ld d, b
    ld b, b
    jp z, $8050

    and b
    or b
    sub $a0
    push hl
    dec bc
    sub $b3
    nop
    and $b0
    sub b
    ld [hl], b
    ld d, b
    jp z, $b060

    push hl
    nop
    db $10
    sub $a0
    dec hl
    sub $b3
    jr nz, jr_01f_6559

jr_01f_6559:
    and $a0
    ld [hl], b
    ld d, b
    jp z, $8050

    and b
    or b
    sub $a0
    push hl
    dec bc
    sub $b3
    nop
    and $b0
    add b
    ld d, b
    ld b, b
    add $d6
    add b
    cp a
    sub $b0
    push hl
    ld b, a
    db $ed
    nop
    ld a, h
    sub $b3
    and $b1
    ret


    or c
    ret


    or c
    push bc
    or c
    rst $08
    push bc
    sub c
    push bc
    or c
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    and c
    sub c
    and c
    or c

Call_01f_65b0:
    and c
    db $fd
    sub b
    ld h, [hl]
    db $fd
    sub b
    ld h, [hl]

Call_01f_65b7:
    db $fd
    sub b
    ld h, [hl]
    jp $c501


    ld bc, $01c5
    push bc
    and $b1
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    and c
    push bc
    sub c
    push bc
    sub c
    push bc
    sub c
    push bc
    sub c
    push bc
    sub c
    push bc
    sub c
    push bc
    and c
    push bc
    and c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    push hl
    ld bc, $01c5
    push bc
    and $b1
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    push hl
    or c
    push bc
    or c
    push bc
    db $e4
    ld bc, $01c5
    push bc
    and $b1
    push bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    db $e4
    ld b, c
    push bc
    ld b, c
    push bc
    ld sp, $31c5
    pop bc
    and $b0
    and b
    add b
    ld h, b

jr_01f_6617:
    ld b, b
    sub $60
    ld c, a
    ld c, d
    sub $b3
    ld b, b
    ld h, b
    add b
    and b
    push hl
    nop
    sub $3f
    rrca
    sub $a0
    ld a, [bc]
    sub $93
    and $b0
    and b
    add b
    ld h, b
    ld b, b
    sub $3f
    ld c, a
    sub $90
    ld c, d
    sub $b3
    ld d, b
    ld [hl], b
    and b
    push hl
    nop
    jr nz, jr_01f_6617

    ccf
    cpl
    sub $a7
    ld a, [hl+]
    jp $edc3


    nop
    add b
    jp $edc3


    nop
    adc b
    jp $edc3


    nop
    sub b
    jp $edc3


    nop
    and b
    jp $edc3


    nop
    ret nz

    jp $edc3


    ld bc, $c320
    jp Jump_000_01ed


    and b
    jp Jump_000_04ed


    nop
    jp Jump_000_00ed


    and b
    jp Jump_01f_43d6


    and $b1
    push bc
    sub $63
    or c
    push bc
    sub $83
    or c
    push bc
    sub $50
    or a
    sub $b3
    or c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    pop bc
    cp $00
    dec c
    ld h, l
    and $b1
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    push hl
    ld bc, $b1e6
    and c
    or c
    push hl
    ld bc, $eaff
    ld a, [bc]
    ld [hl-], a
    db $ec
    inc bc
    sub $c3
    push hl
    ld b, b
    ld h, b
    add b
    and b
    db $e4
    nop
    sub $b0
    dec bc
    sub $c3
    ld bc, $b0e5
    and b
    add b
    ld h, b
    ld b, b
    ld b, c
    pop bc
    and $71
    push bc
    ld h, c
    push bc
    ld [hl], c
    push bc
    add c
    pop bc
    ld b, c
    pop bc
    ld [hl], c
    push bc
    ld [hl], c
    push bc
    ld [hl], c
    push bc
    ld h, c
    push bc
    ld [hl], c
    push bc
    add c
    pop bc
    ld b, c
    pop bc
    add c
    push bc
    add c
    push bc
    add c
    push bc
    add c
    push bc
    add c
    push bc
    add c
    pop bc
    sub $b7
    db $ec
    ld [bc], a
    db $e4
    ld b, a
    scf
    ld b, a
    ld d, a
    ld b, a
    scf
    daa
    scf
    ld b, a
    ld d, a
    ld h, a
    ld [hl], a
    add a
    scf
    daa
    scf
    db $ec
    inc bc
    sub $6f
    ld c, a
    sub $c0
    cp a
    sub $c4
    push hl
    ld b, e
    inc sp
    ld b, e
    ld d, e
    ld b, e
    inc sp
    inc hl
    inc sp
    ld b, e
    ld d, e
    ld h, e
    ld [hl], e
    add e
    inc sp
    inc hl
    inc sp
    sub $c2
    db $ec
    ld bc, $43e4
    inc sp
    ld b, e
    ld d, e
    ld b, e
    inc sp
    inc hl
    inc sp
    ld b, e
    sub $c4
    db $ec
    inc bc
    push hl
    ld d, e
    ld h, e
    ld [hl], e
    add e
    inc sp
    inc hl
    inc sp
    ld b, e
    inc sp
    ld b, e
    sub $c0
    ld d, a
    sub $b7
    ld d, a
    sub $8a
    ld d, e
    sub $c4
    db $ec
    inc bc
    ld d, e
    ld b, e
    ld d, e
    sub $a0
    ld h, a
    sub $b0
    ld h, a
    sub $99
    ld h, e
    sub $c4
    ld h, e
    ld d, e
    ld h, e
    sub $90
    ld a, e
    sub $59
    ld [hl], a
    sub $c4
    ld [hl], e
    ld h, e
    ld [hl], e
    ld h, e
    ld d, e
    ld h, e
    ld d, e
    ld b, e
    ld d, e
    ld b, e
    inc sp
    inc hl
    inc de
    inc hl
    inc sp
    inc hl
    sub $c2
    db $ec
    ld bc, $6353
    ld [hl], e
    add e
    sub e
    sub $b4
    db $ec
    inc bc
    inc sp
    inc hl
    inc sp
    sub $c2
    db $ec
    ld bc, $6353
    ld [hl], e
    add e
    and e
    sub $b4
    db $ec
    inc bc
    inc sp
    inc hl
    inc sp
    sub $c2
    db $ec
    ld bc, $6353
    ld [hl], e
    add e
    or e
    sub $b4
    db $ec
    inc bc
    inc sp
    inc hl
    inc sp
    sub $c2
    db $ec
    ld bc, $6353
    ld [hl], e
    add e
    db $e4
    inc bc
    sub $b4
    db $ec
    inc bc
    push hl
    inc sp
    inc hl
    inc sp
    jp $c571


    ld [hl], c
    push bc
    ld [hl], c
    push bc
    ld [hl], c

Call_01f_67b7:
    pop bc
    db $ec
    nop
    db $e4
    ld b, c
    pop bc
    add c
    push bc
    add c
    push bc
    add c
    push bc
    add c
    push bc
    db $ec
    inc bc
    push hl
    ld [hl], c
    push bc
    ld [hl], c
    push bc
    ld [hl], c
    push bc
    ld [hl], c
    pop bc
    db $ec
    nop
    db $e4
    ld b, c
    pop bc
    or c
    push bc
    or c
    push bc
    or c
    push bc
    or c
    pop bc
    db $ec
    inc bc
    push hl
    ld [hl], c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    db $e4
    ld bc, $e5c1
    ld [hl], c
    pop bc
    db $e4
    ld bc, $e5c1
    ld [hl], c
    pop bc
    db $e4
    ld bc, $e5c1
    ld [hl], c
    pop bc
    db $e4
    ld bc, $e5c1
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    ld b, c
    pop bc
    ld [hl], c
    pop bc
    db $e4
    ld bc, $e5c1
    ld [hl], c
    pop bc
    ld b, c
    pop bc
    ld [hl], c
    pop bc
    or c
    pop bc
    ld [hl], c
    pop bc
    db $e4
    ld bc, $e5c1
    ld [hl], c
    pop bc
    sub $87
    db $e3
    ld b, e
    inc sp
    ld b, e
    ld d, e
    ld b, e
    inc sp
    inc hl
    inc sp
    ld b, e
    ld d, e
    ld h, e
    ld [hl], e
    add e
    inc sp
    inc hl
    inc sp
    jp Jump_01f_43d6


    and $71
    push bc
    sub $63
    ld h, c
    push bc
    sub $83
    ld [hl], c
    push bc
    sub $4f
    add a
    sub $b4
    ld [hl], c
    push bc
    ld h, c
    push bc
    ld [hl], c
    push bc
    add c
    pop bc
    cp $00
    adc $66
    ld [$1108], a
    call c, $cb11
    db $e3
    ld b, e
    inc sp
    ld b, e
    ld d, e
    ld b, e
    inc sp
    inc hl
    inc sp
    ld b, e
    ld d, e
    ld h, e
    ld [hl], e
    add e

jr_01f_6872:
    inc sp
    inc hl
    inc sp
    ld b, b
    ret nz

    ld [hl], b
    jp nz, $c260

    ld [hl], b

jr_01f_687c:
    jp nz, $c080

    ld b, b
    ret nz

    ld [hl], b
    jp nz, $c280

    ld [hl], b
    jp nz, $c260

    ld [hl], b
    jp nz, $c080

    ld d, b
    ret nz

    add b
    jp nz, $c280

    ld [hl], b
    jp nz, $c080

    ld b, b
    ret nz

    add b
    jp nz, $c270

    ld [hl], b
    jp nz, $c270

    ld [hl], b
    jp nz, $c070

    db $e4
    ld b, b
    call nz, $c450
    ld d, b
    jp nz, $ca40

    jr nc, jr_01f_6872

    ld b, b
    call nz, $c450
    ld d, b
    jp nz, $ca40

    jr nc, jr_01f_687c

    ld b, b
    ret nz

    ld d, b
    jp nz, $c250

    ld d, b
    jp nz, $c050

    ld d, b
    ret nz

    ld h, b
    jp nz, $c260

    ld h, b
    jp nz, $c060

    ld h, b
    ret nz

    ld [hl], b
    jp nz, $c270

    ld [hl], b
    jp nz, $c270

    ld [hl], b
    jp nz, $c260

    ld d, b
    jp nz, $c240

    ld d, b
    jp nz, $c240

    jr nc, @-$3c

    jr nz, @-$3e

    daa
    ld d, a
    daa
    ld h, a
    daa
    ld [hl], a
    daa
    sub a
    ld b, e
    inc sp
    ld b, e
    ld d, e
    db $e3
    ld b, c
    ld sp, $5141
    ld b, c
    ld sp, $3121
    db $e4
    ld b, e
    inc sp
    ld b, e
    ld d, e
    db $e3
    ld b, c
    ld d, c
    ld h, c
    ld [hl], c
    add c
    ld sp, $3121
    ld [c], a
    ld b, e
    inc sp
    ld b, e
    ld d, e
    ld b, e
    inc sp
    inc hl
    inc sp
    ld b, e
    ld d, e
    ld h, e
    ld [hl], e
    add e
    inc sp
    inc hl
    inc sp
    sub $11
    jp $c3c3


    jp $c3c3


    jp $c3c3


    jp $c3c3


    jp $c3c3


    jp Jump_000_11dc


    jp $c3c3


    jp Jump_01f_43e3


    inc sp
    ld b, e
    ld d, e
    cp $00
    ld l, c
    ld l, b
    db $ed
    nop
    ld a, h
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    add sp, -$24
    or c
    jp $21e5


    ld de, $4fdc
    inc hl
    call c, $23a1
    inc hl
    inc hl
    call c, Call_000_2370
    cp $00
    ld c, [hl]
    ld l, c
    db $ec
    ld bc, $b6dc
    push hl
    or c
    and c
    or a
    call c, $e4c2
    ld sp, $1121
    ld bc, $b3e5
    or e
    or e
    or e
    or e
    call c, $a34f
    call c, Call_01f_71c2
    add c
    sub c
    and c
    or e
    or e
    or e
    or e
    or e
    call c, $a33f
    call c, $fec2
    nop
    ld h, d
    ld l, c
    call c, $c710
    db $e4
    ld h, b
    ret nz

    ld d, b
    ret nz

    ld h, b
    jp nz, $c260

    ld h, b
    jp nz, $fea3

    nop
    adc [hl]
    ld l, c
    db $ed
    nop
    ld a, h
    ldh a, [rPCM34]
    db $ec
    ld bc, $dce8
    or d
    push hl
    add l
    db $e4
    ld b, c
    ld sp, $0111
    call c, $e581
    ld b, e
    cp $0c
    xor h
    ld l, c
    ld b, e
    and $b3
    or e
    push hl
    ld b, e
    cp $00
    xor h
    ld l, c
    db $ec
    ld [bc], a
    call c, $e5c2
    or c
    call c, $e4c7
    cp e
    call c, $e5c2
    or e
    db $e4
    inc sp
    ld b, e
    inc sp
    ld de, $e501
    or c
    sub c
    add c
    sub c
    and c
    db $e4
    ld de, $b3e5
    db $e4
    inc de
    push hl
    or e
    sub e
    add c
    ld h, c
    ld b, c
    ld sp, $6141
    add c
    sub c
    cp $00
    add $69
    call c, $c710
    db $e3
    db $10
    ret nz

    db $e4
    or b
    ret nz

    sub b
    ret nz

    db $fd
    db $10
    ld l, d
    add b
    jp nz, $c240

    add b
    jp nz, $c240

    db $fd
    db $10
    ld l, d
    add b
    jp nz, $c240

    add b
    jp nz, $c2b0

    cp $00
    or $69
    add b
    jp nz, $c240

    add b
    jp nz, $c040

    ld h, b
    ret nz

    rst $38
    db $ed
    nop
    ld [hl], b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3314], a
    add sp, -$24
    or h
    push hl
    db $10
    jr nz, jr_01f_6a5c

    ld b, b
    ld e, e
    rst $08
    push hl
    or e
    sub e
    add c
    ld h, c
    ld b, c
    ld sp, $4563
    ld d, c
    ld h, e
    ld [hl], a
    db $e4
    daa
    ld c, a
    cp $00
    cpl
    ld l, d
    db $ec
    inc bc
    ld [$2218], a
    call c, $e4c4
    ld b, b
    jr nc, jr_01f_6a6d

    db $10
    push hl
    cp e
    pop bc
    ld b, b
    jp nz, $c840

    call c, $e4c4
    ld b, l
    dec [hl]
    inc de
    push hl

jr_01f_6a5c:
    or c
    sub c
    add c
    ld h, c
    add c
    sub c
    or c
    db $e4
    ld de, $c7dc
    ld e, a
    call c, $e5c5
    ld h, a
    db $e4

jr_01f_6a6d:
    rla
    cp $00
    ld d, l
    ld l, d
    call c, $c510
    db $e4
    or b

jr_01f_6a77:
    ret nz

    ld b, b
    ret nz

    or b
    jp nz, $c0b0

    ld b, b
    ret nz

    or b
    jp nz, $c2b0

    ld b, b
    ret nz

    ld d, b
    ret nz

    ld h, b

jr_01f_6a89:
    ret nz

    ld b, b
    ret nz

    or b
    ret nz

    ld b, b
    ret nz

    or b
    ret nz

    ld b, b
    ret nz

    or b
    ret nz

    ld b, b
    ret nz

    or b
    ret nz

    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4

jr_01f_6aa0:
    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4
    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4
    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4
    ld [hl], b
    ret nz

    db $e3
    jr nz, jr_01f_6a77

    db $e4
    ld [hl], b
    ret nz

    db $e3
    jr nz, @-$3e

    db $e4
    ld [hl], b
    ret nz

    db $e3
    jr nz, @-$3e

    db $e4
    ld [hl], b
    ret nz

    db $e3
    jr nz, jr_01f_6a89

    db $e4
    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4
    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4
    ld h, b
    ret nz

    db $e3
    db $10
    ret nz

    db $e4
    ld h, b
    ret nz

    jr nc, jr_01f_6aa0

    cp $00
    adc d
    ld l, d
    db $ed
    nop
    ld h, [hl]
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3406], a
    add sp, -$24
    or c
    rst $00
    and $91
    sub c
    call c, $e5b4
    inc hl
    call c, $e6b1
    sub c
    sub c
    call c, $e5b4
    inc sp
    call c, $e6b1
    sub c
    sub c
    call c, $e5b4
    inc hl
    call c, $e6b1
    sub c
    sub c
    call c, $a3a0
    call c, $91b1
    sub c
    call c, $e5b4
    inc hl
    call c, $e6b1
    sub c
    sub c
    call c, $e529
    ld [hl], e
    call c, $97b0
    and $97
    call c, $e5b7
    ld d, a
    call c, $e64f
    ld d, a
    call c, $91b1
    sub c
    call c, $e5b4
    inc hl
    call c, $e6b1
    sub c
    sub c
    call c, $e5b4
    inc sp
    call c, $e6b1
    sub c
    sub c
    call c, $e5b4
    ld d, e
    call c, $e6b1
    sub c
    sub c
    call c, $e5b4
    ld [hl], e
    call c, Call_01f_6fb0
    call c, $e4b1
    cpl
    rst $38
    db $ec
    inc bc
    ld [$2508], a
    call c, $c7c2
    push hl
    ld hl, $dc21
    push bc
    sub e
    call c, $21c2
    ld hl, $c5dc
    and e
    call c, $21c2
    ld hl, $c5dc
    sub e
    call c, $21c2
    ld hl, $b7dc
    inc de
    call c, $21c2
    ld hl, $c5dc

jr_01f_6b85:
    sub e
    call c, $e5c2
    ld hl, $dc21
    rst $00

jr_01f_6b8d:
    db $e4
    inc de

jr_01f_6b8f:
    daa
    push hl
    daa

jr_01f_6b92:
    db $e4
    rlca

jr_01f_6b94:
    push hl
    rlca
    call c, $21c2

jr_01f_6b99:
    ld hl, $c5dc

jr_01f_6b9c:
    sub e
    call c, $21c2
    ld hl, $c5dc
    and e
    call c, $21c2

jr_01f_6ba7:
    ld hl, $c5dc

jr_01f_6baa:
    db $e4
    inc bc

jr_01f_6bac:
    call c, $e5c2

jr_01f_6baf:
    ld hl, $dc21
    push bc
    db $e4

jr_01f_6bb4:
    inc de
    call c, $2f2f
    call c, $e3c1
    cpl
    rst $38
    call c, $c710
    db $e4
    jr nz, @-$3e

    jr nz, jr_01f_6b85

    sub e
    jr nz, @-$3e

jr_01f_6bc8:
    jr nz, @-$3e

    sub e
    jr nz, jr_01f_6b8d

    jr nz, jr_01f_6b8f

    sub e
    jr nz, jr_01f_6b92

    jr nz, jr_01f_6b94

    ld h, e
    jr nz, @-$3e

    jr nz, jr_01f_6b99

    sub e
    jr nz, jr_01f_6b9c

    jr nz, @-$3e

    and e
    sub a
    daa
    and a
    daa
    jr nz, @-$3e

    jr nz, jr_01f_6ba7

    sub e
    jr nz, jr_01f_6baa

    jr nz, jr_01f_6bac

    sub e
    jr nz, jr_01f_6baf

    jr nz, @-$3e

    and e
    jr nz, jr_01f_6bb4

    jr nz, @-$3e

    and e
    sbc a
    jr nz, jr_01f_6bc8

    rst $38
    sub $b0
    inc de
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    ld [de], a
    or b
    inc de
    or b
    ld [de], a
    or b
    inc de
    or b
    ld [de], a
    or b
    inc de
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld de, $11b0
    or e
    ld de, $11b3
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or e
    ld de, $11b3
    or a
    ld de, $11b3
    or e
    ld de, $11b7
    or e
    ld de, $11b3
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or e
    ld de, $11b3
    or a
    ld de, $11b3
    or e
    ld de, $11b3
    or b
    inc de
    or b
    inc de
    or b
    ld [de], a
    or b
    ld [de], a
    cp a
    ld de, $11bf
    cp a
    ld de, $13b0
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    ld [de], a
    or b
    inc de
    or b
    ld [de], a
    or b
    inc de
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld de, $11b0
    or b
    ld de, $11b0
    or e
    ld de, $11b3
    or a
    ld de, $11b3
    or e
    ld de, $13b0
    or b
    inc de
    or b
    inc de
    or b
    inc de
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or b
    ld [de], a
    or e
    ld de, $11b3
    or a
    ld de, $11b3
    or a
    ld de, $11b3
    cp a
    ld de, $11bf
    or c
    ld de, $cdcf
    rst $38
    db $ed
    nop
    and b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$340c], a
    add sp, -$24
    or l
    push bc
    and $91
    add d
    ld h, b
    ld b, l
    push hl
    add c
    ld h, c
    add e
    call c, $41b2
    ld b, e
    ld b, c
    ld b, e
    ld hl, $2123
    inc hl
    ld hl, $dc23
    or c
    ld h, d
    call c, Call_000_22b2
    ld b, c
    ld b, e
    ld b, c
    ld b, e
    sub c
    sub e
    add c
    add e
    ld h, c
    ld h, e
    ld b, c
    ld b, e
    add c
    add e
    call c, Call_01f_62b1
    call c, $80b2
    call c, $91b4
    or c
    db $e4
    ld bc, $b7dc
    dec d
    call c, $21b3
    ld de, $b1e5
    sub c
    add c
    ld h, c
    ld b, c
    ld h, c
    add c
    sub c
    add c
    ld h, c
    add c
    ld h, c
    ld b, c
    add c
    ld h, c
    add c
    sub c
    add c
    ld h, c
    add c
    sub c
    or c
    db $e4
    ld hl, $e511
    or c
    sub c
    add c
    ld h, c
    ld b, c
    ld h, c
    add c
    sub c
    add c
    sub c
    ld b, c
    add c
    or c
    db $e4
    ld hl, $e511
    or c
    db $e4
    ld de, $b1e5
    sub c
    add c
    ld h, c
    ld b, e
    cp $00
    ret nc

    ld l, h
    db $ec
    inc bc
    ld [$2510], a
    call c, $e5c6
    sub c
    add d
    ld h, b
    ld b, l
    add l
    db $e4
    ld b, c
    ld hl, $b1e5
    call c, $e4c6
    ld b, l
    inc d
    ld b, b
    dec h
    push hl
    or l
    db $e4
    dec h
    push hl
    or c
    call c, $e4c1
    ld h, d
    call c, $20c6
    ld b, l
    dec d
    ld b, l
    inc d
    ld b, b
    ld h, l
    dec h
    ld h, l
    ld b, c
    call c, Call_01f_62c1
    call c, $40c6
    sub l
    sub l
    or c
    sub d
    jr nz, jr_01f_6ddc

    ld b, c
    ld h, d
    ld b, b
    dec d
    ld hl, $e512
    or b
    db $e4
    ld h, l
    ld b, c
    ld [hl-], a
    ld b, b
    sub l
    or c
    sub d
    jr nz, jr_01f_6dee

    ld b, c
    ld h, d
    add b
    sub l
    add c
    ld h, d
    ld b, b
    add l
    sub c
    add d
    sub b
    db $e3
    dec d
    cp $00
    ld c, [hl]
    ld l, l
    call c, $cb10
    db $e3
    ld b, l
    db $e4
    ld b, c
    ld h, c
    add c
    push hl
    sub c
    db $e4
    sub c
    sub c
    ld b, c
    sub c
    sub c
    push hl
    or c
    db $e4
    add c
    add c
    ld b, c
    add c
    add c
    push hl
    or c
    db $e4
    add c
    add c
    ld b, c
    add b
    pop bc
    ld b, b
    ld de, $9191
    ld b, c
    sub c
    sub c
    ld de, $9191
    ld b, c
    sub c
    sub c
    push hl
    or c
    db $e4
    add c
    add c
    ld b, c
    add c
    add c
    push hl
    or c
    db $e4
    add c
    add c
    ld b, c
    add b
    pop bc
    ld b, b
    ld de, $9191

jr_01f_6ddc:
    ld b, c
    sub c
    sub c
    ld hl, $6161
    push hl
    sub c
    db $e4
    ld h, c
    ld h, c
    ld b, c
    sub c
    sub c
    ld de, $9191
    ld b, c

jr_01f_6dee:
    add c
    add c
    push hl
    or c
    db $e4
    add c
    add c
    ld b, c
    sub c
    sub c
    push hl
    sub c
    db $e4
    sub c
    sub c
    ld hl, $6161
    push hl
    sub c
    db $e4
    ld h, c
    ld h, c
    ld b, c
    sub c
    sub c
    ld de, $9191
    ld b, c
    add c
    add c
    push hl
    or c
    db $e4
    add c
    add c
    ld b, c
    sub c
    sub c
    ld de, $4121
    cp $00
    and e
    ld l, l
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    ld [$2408], a
    db $ec
    ld [bc], a
    db $fc
    and l
    add sp, -$23
    ld h, a
    db $e4
    ld b, a
    call c, $b167
    add l
    ld h, a
    add c
    sub l
    add a
    ld h, e
    add e
    ld c, c
    rst $38
    ld [$1505], a
    db $ec
    ld [bc], a
    db $fc
    ld a, [bc]
    call c, $e4a7
    ld b, a
    or c
    add l
    ld h, a
    add c
    sub l
    add a
    ld h, e
    add e
    ld c, c
    rst $38
    db $ed
    nop
    ld [hl], b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$220c], a
    add sp, -$24
    or e
    rst $08
    rst $08
    rst $08
    set 4, l
    jr nz, jr_01f_6ea3

    ld d, b
    ld h, b
    call c, $e480
    rrca
    ld c, a
    ld l, a
    call c, Call_01f_5f60
    cp $03
    ld h, l
    ld l, [hl]
    rst $08
    rst $08
    rst $08
    rst $08
    cp $00
    ld h, l
    ld l, [hl]
    ld [$2508], a
    db $ec
    inc bc
    call c, $e5c4
    ld [hl], c
    ld hl, $9971
    ld [hl], c
    ld hl, $e471
    inc bc
    push hl
    or e
    sub c
    ld [hl], c
    ld hl, $9971
    ld d, c
    ld bc, $a351
    sub e
    ld d, c
    cp $00
    ld a, a
    ld l, [hl]
    call c, $e412
    ld hl, $2171
    ld [hl], c

jr_01f_6ea3:
    ld hl, $2171
    ld [hl], c
    cp $0c
    sbc [hl]
    ld l, [hl]
    inc hl
    ld [hl], e
    inc hl
    ld [hl], e
    ld b, e
    ld [hl], e
    ld b, e
    ld [hl], e
    ld h, e
    sub e
    ld h, e
    sub e
    ld b, e
    ld [hl], e
    ld b, e
    ld [hl], e
    cp $00
    sbc h
    ld l, [hl]
    rst $38
    rst $38
    rst $38
    rlca
    cp h
    ld [hl], c
    rlca
    ret nz

    ld [hl], c
    rlca
    call nz, Call_000_0771
    ret z

    ld [hl], c
    rlca
    call z, Call_000_0771
    rst $18
    ld [hl], c
    rlca
    db $e3
    ld [hl], c
    rlca
    ld [$0771], a
    xor $71
    rlca
    ld a, [c]
    ld [hl], c
    rlca
    or $71
    rlca
    ld a, [$0771]
    cp $71
    rlca
    ld [bc], a
    ld [hl], d
    rlca
    ld b, $72
    rlca
    dec c
    ld [hl], d
    rlca
    inc d
    ld [hl], d
    rlca
    jr jr_01f_6f6a

    rlca
    inc e
    ld [hl], d
    add h
    xor l
    ld a, b
    dec b
    cp h
    ld a, b
    rlca
    bit 7, b
    add h
    cp l
    ld a, d
    dec b
    ret nc

    ld a, d
    rlca
    db $e3
    ld a, d
    add h
    ld [hl-], a
    ld a, d
    dec b
    ld b, c
    ld a, d
    rlca
    ld c, a
    ld a, d
    add h
    call z, $0577
    db $eb
    ld [hl], a
    rlca
    ld a, [bc]
    ld a, b
    add h
    ld a, e
    ld a, e
    dec b
    sbc d
    ld a, e
    rlca
    cp c
    ld a, e
    add h
    ld e, e
    ld a, c
    dec b
    ld l, [hl]
    ld a, c
    rlca
    add b
    ld a, c
    add h
    dec b
    ld a, c
    dec b
    rra
    ld a, c
    rlca
    jr nz, jr_01f_6fb3

    add h
    inc sp
    ld a, c
    dec b
    ld b, d
    ld a, c
    rlca
    ld d, c
    ld a, c
    add h
    ld c, e
    ld a, e
    dec b
    ld e, [hl]
    ld a, e
    rlca
    ld [hl], c
    ld a, e
    add h
    ld d, l
    db $76
    dec b
    ld [hl], d
    db $76
    rlca
    sub e
    db $76
    add h
    ldh a, [$7a]
    dec b
    rrca
    ld a, e
    rlca
    ld [hl-], a
    ld a, e
    add h
    add c
    ld a, c
    dec b
    xor h
    ld a, c
    rlca
    bit 7, c
    add h
    db $e4
    ld a, c

jr_01f_6f6a:
    dec b
    dec bc
    ld a, d
    rlca
    ld sp, $847a
    ld d, b
    ld a, d
    dec b
    ld l, a
    ld a, d
    rlca
    sbc [hl]
    ld a, d
    add h
    push de
    ld a, b
    dec b
    add sp, $78
    rlca
    ei
    ld a, b
    add h
    rla
    ld a, b
    dec b
    ld [hl-], a
    ld a, b
    rlca
    ld c, l
    ld a, b
    add h
    ld e, l
    ld a, b
    dec b
    add b
    ld a, b
    rlca
    and e
    ld a, b
    add h
    add hl, sp
    ld [hl], a
    dec b
    ld e, b
    ld [hl], a
    rlca
    ld a, e
    ld [hl], a
    add h
    ld d, c
    ld a, h
    dec b
    ld h, h
    ld a, h
    rlca
    ld [hl], a
    ld a, h
    add h
    add h
    ld a, h
    dec b
    sbc a
    ld a, h
    rlca
    cp d
    ld a, h
    add h

Call_01f_6fb0:
    call Call_000_057c

jr_01f_6fb3:
    call c, $077c
    db $eb
    ld a, h
    add h
    ld e, e
    ld a, l
    dec b
    db $76
    ld a, l
    rlca
    sub c
    ld a, l
    add h
    xor $7b
    dec b
    db $fd
    ld a, e
    rlca
    inc c
    ld a, h
    add h
    and h
    ld a, l
    dec b
    or a
    ld a, l
    rlca
    jp z, $847d

    or h
    ld a, [hl]
    dec b
    rst $10
    ld a, [hl]
    rlca
    ld a, [$847e]
    call z, $057b
    db $db
    ld a, e
    rlca
    db $ed
    ld a, e
    add h
    dec h
    ld a, [hl]
    dec b
    ld b, b
    ld a, [hl]
    rlca
    ld e, e
    ld a, [hl]
    add h
    ld d, $7c
    dec b
    dec l
    ld a, h
    rlca
    ld b, h
    ld a, h
    add h
    rst $10
    ld a, l
    dec b
    ld a, [$077d]
    dec d
    ld a, [hl]
    add h
    ld l, [hl]
    ld a, [hl]
    dec b
    adc c
    ld a, [hl]
    rlca
    and h
    ld a, [hl]
    add h
    push af
    ld a, h
    dec b
    jr jr_01f_708c

    rlca
    ccf
    ld a, l
    add h
    dec c
    ld a, a
    dec b
    jr nz, jr_01f_7097

    rlca
    inc sp
    ld a, a
    add h
    ld b, b
    ld a, a
    dec b
    ld d, e
    ld a, a
    rlca
    ld h, [hl]
    ld a, a
    add h
    ld [hl], e
    ld a, a
    dec b
    sub [hl]
    ld a, a
    rlca
    cp b
    ld a, a
    add h
    cp c
    ld a, a
    dec b
    call z, Call_000_077f
    rst $18
    ld a, a
    add h
    xor h
    db $76
    dec b
    jp $0776


    sub $76
    add h
    db $e3
    db $76
    dec b
    ld b, $77
    rlca
    add hl, hl
    ld [hl], a
    add h
    sub c
    ld [hl], a
    dec b
    xor b
    ld [hl], a
    rlca
    cp a
    ld [hl], a
    add h
    ldh a, [$5a]
    dec b
    rlca
    ld e, e
    ld b, $17
    ld e, e
    add h
    ret z

    ld h, b
    dec b
    rst $20
    ld h, b
    ld b, $ff
    ld h, b
    inc b
    or d
    ld [hl], d
    inc b
    ld c, a
    ld [hl], e
    inc b
    ld [hl], c
    ld [hl], e
    rlca
    add d
    ld [hl], d
    inc b
    ld a, [bc]
    ld [hl], e
    add h
    ld a, d
    ld h, b
    dec b
    sub e
    ld h, b
    ld b, $a9
    ld h, b
    add h
    inc d
    ld h, c
    dec b
    inc sp
    ld h, c
    ld b, $4f
    ld h, c
    inc b
    ld e, [hl]
    ld [hl], e
    inc b
    add [hl]
    ld [hl], e
    inc b
    sub l

jr_01f_708c:
    ld [hl], e
    inc b
    call nz, $0473
    rst $10
    ld [hl], e
    inc b
    ld [$0473], a

jr_01f_7097:
    dec b
    ld [hl], h
    inc b
    inc e
    ld [hl], h
    inc b
    ld sp, $0474
    ld c, h
    ld [hl], h
    inc b
    ld h, a
    ld [hl], h
    inc b
    ld [hl], d
    ld [hl], h
    rlca
    ld a, l
    ld [hl], h
    rlca
    adc d
    ld [hl], h
    ld b, h
    cp e
    ld [hl], h
    dec b
    jp nc, Jump_000_0474

    push hl
    ld [hl], h
    rlca
    ldh a, [$74]
    ld b, h
    add hl, bc
    ld [hl], l
    dec b
    jr z, jr_01f_7135

    inc b
    ld b, a
    ld [hl], l
    rlca

Call_01f_70c4:
    adc c
    ld [hl], d
    rlca
    sbc c
    ld [hl], d
    ld b, h
    and b
    ld [hl], d
    dec b
    and a
    ld [hl], d
    ld b, h
    jp $0572


    jp z, $4472

    push de
    ld [hl], d
    dec b
    ldh [$72], a
    inc b
    rst $28
    ld [hl], d
    rlca
    ld a, [$4472]
    dec e
    ld [hl], e
    dec b
    inc [hl]
    ld [hl], e
    rlca
    ld h, h
    ld [hl], l
    rlca
    ld a, l
    ld [hl], l
    rlca
    add c
    ld [hl], l
    rlca
    add l
    ld [hl], l
    rlca
    adc a
    ld [hl], l
    rlca
    sub [hl]
    ld [hl], l
    inc b
    and [hl]
    ld [hl], l
    inc b
    or l
    ld [hl], l
    ld b, h
    ret nz

    ld [hl], l
    dec b
    rst $08
    ld [hl], l
    inc b
    sbc $75
    ret nz

    ld h, b
    ld d, a
    ld bc, $5818
    ld [bc], a
    db $e3
    ld e, b
    inc bc
    adc e
    ld e, c
    add b
    nop
    ld b, b
    ld bc, $4140
    ld [bc], a
    and e
    ld b, d
    add b
    ld c, a
    ld l, [hl]
    ld bc, $6e7a
    ld [bc], a
    sbc h
    ld l, [hl]
    add b
    ld e, c
    ld h, c
    ld bc, $61a5
    ld [bc], a
    ld a, [c]
    ld h, c
    ld b, b
    dec e
    ld l, [hl]
    ld bc, $6e3a

jr_01f_7135:
    ret nz

    ld e, e
    ld c, [hl]
    ld bc, $4f0c
    ld [bc], a
    or h
    ld c, a
    inc bc
    ld [$8051], sp
    cp c
    ld l, h
    ld bc, $6d3c
    ld [bc], a
    sbc d
    ld l, l
    add b

jr_01f_714b:
    xor e
    ld d, h
    ld bc, $557f
    ld [bc], a
    dec hl
    ld d, [hl]
    ret nz

    db $e4
    ld l, d
    ld bc, $6b5c
    ld [bc], a
    cp l
    ld l, e
    inc bc
    ei
    ld l, e
    ret nz

    ld [hl], c
    ld d, c
    ld bc, $527e
    ld [bc], a
    ld a, h

jr_01f_7167:
    ld d, e
    inc bc
    ld a, [hl+]
    ld d, h
    ret nz

    daa

jr_01f_716d:
    ld e, e
    ld bc, $5b78
    ld [bc], a

jr_01f_7172:
    db $db

jr_01f_7173:
    ld e, e
    inc bc
    ld a, h

jr_01f_7176:
    ld e, h
    ret nz

    sub c
    ld e, h

jr_01f_717a:
    ld bc, $5e08
    ld [bc], a
    ld a, [de]

jr_01f_717f:
    ld e, a
    inc bc
    add h
    ld e, a
    ret nz

    xor a
    ld e, a
    ld bc, $5fe0
    ld [bc], a
    ld e, $60
    inc bc
    ld d, b
    ld h, b
    add b
    ld [$0162], a
    add e
    ld h, e
    ld [bc], a
    ld a, [hl-]
    ld h, h
    add b
    db $e3
    ld h, h
    ld bc, $66a9
    ld [bc], a
    ld e, [hl]
    ld l, b
    add b

jr_01f_71a2:
    dec a
    ld l, c
    ld bc, $695a

jr_01f_71a7:
    ld [bc], a
    add [hl]

jr_01f_71a9:
    ld l, c
    add b
    sbc c
    ld l, c
    ld bc, $69bc
    ld [bc], a
    db $eb
    ld l, c
    add b

Call_01f_71b4:
    dec de
    ld l, d
    ld bc, $6a42
    ld [bc], a
    ld [hl], d
    ld l, d
    jr nz, jr_01f_717f

    inc sp
    rst $38
    jr nz, jr_01f_7173

Call_01f_71c2:
    inc sp
    rst $38
    jr nz, jr_01f_7167

    inc sp
    rst $38
    jr nz, jr_01f_714b

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
    inc [hl]
    inc hl
    add d
    inc sp
    ld [hl+], a
    add c
    ld [hl-], a
    rst $38
    jr nz, jr_01f_7232

    ld a, [hl+]
    rst $38
    ld hl, $2b41
    jr nz, @+$63

    ld a, [hl+]
    rst $38
    jr nz, jr_01f_716d

    db $10
    rst $38
    jr nz, jr_01f_7172

    inc hl
    rst $38
    jr nz, jr_01f_7176

    dec h
    rst $38
    jr nz, jr_01f_717a

    ld h, $ff
    jr nz, @-$5d

    db $10
    rst $38
    jr nz, jr_01f_71a2

    ld de, $20ff
    and d
    ld d, b
    rst $38
    jr nz, jr_01f_71a9

    jr jr_01f_722a

    ld sp, $ff33
    ld [hl+], a
    sub c
    jr z, jr_01f_7231

    ld [hl], c
    jr @+$01

    jr nz, jr_01f_71a7

    ld [hl+], a
    rst $38
    jr nz, jr_01f_728b

    ld [hl+], a
    rst $38
    jr nz, jr_01f_727f

    ld [hl+], a
    rst $38
    ld [hl-], a
    ld [hl], d
    ld b, d
    ld [hl], d
    ld d, d
    ld [hl], d
    ld h, d
    ld [hl], d
    ld [hl], d
    ld [hl], d

jr_01f_722a:
    add d
    ld [hl], d
    add d
    ld [hl], d
    add d
    ld [hl], d
    add d

jr_01f_7231:
    ld [hl], d

jr_01f_7232:
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

jr_01f_7260:
    sub [hl]
    ld sp, $4602
    adc d
    call $feef

jr_01f_7268:
    sbc $ff
    xor $dc
    cp d
    sbc b
    db $76

jr_01f_726f:
    ld d, h
    ld [hl-], a
    db $10
    ld bc, $4523
    ld h, a
    adc d
    call $f7ee
    ld a, a
    xor $dc
    xor b
    db $76

jr_01f_727f:
    ld d, h
    ld [hl-], a
    db $10
    ld hl, $33e2

jr_01f_7285:
    jr z, jr_01f_7268

    ld [hl+], a

jr_01f_7288:
    rst $38
    ld [hl+], a
    rst $30

jr_01f_728b:
    inc h
    ld [hl+], a
    rst $30
    inc [hl]
    inc h
    rst $30
    ld b, h
    jr z, jr_01f_7288

    ld d, l
    jr z, jr_01f_7288

    ld b, h
    rst $38
    add hl, hl
    pop af
    ld b, h
    jr z, jr_01f_726f

    ld b, e

jr_01f_729f:
    rst $38

jr_01f_72a0:
    db $ec
    ld [bc], a
    jr z, jr_01f_7285

    ld b, b
    rlca
    rst $38

jr_01f_72a7:
    db $ec
    ld [bc], a
    ld [hl+], a
    ld [$0000], sp
    jr z, jr_01f_7260

    ld b, c
    rlca
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
    jr z, jr_01f_72a0

    nop
    ld [bc], a
    db $10
    ld [$ecff], sp
    ld [bc], a
    inc h
    pop af
    add b
    rlca
    rst $38
    db $ec
    ld [bc], a
    ld hl, $0008

jr_01f_72cf:
    nop
    inc h
    and c
    ld h, c
    rlca
    rst $38
    db $ec
    ld [bc], a
    inc h
    pop hl
    nop
    rlca
    jr z, jr_01f_72cf

    ldh [rTAC], a
    rst $38
    db $ec
    ld [bc], a
    ld hl, $0008
    nop
    inc h
    sub c
    pop bc
    ld b, $28
    and d
    and c
    rlca
    rst $38
    db $ec
    ld [bc], a
    db $10
    ld e, d
    cpl
    pop af
    nop
    inc bc
    db $10
    ld [$22ff], sp
    pop af
    ld d, h
    inc l
    ld [hl], c
    inc hl
    ld [hl+], a
    or c
    ld d, h
    inc l
    ld h, c
    inc hl
    ld h, $41
    ld d, h
    rst $38
    db $ec
    ld [bc], a
    jr nz, jr_01f_729f

    ret nz

    rlca
    jr nz, @-$7d

    ret nc

    rlca
    jr nz, jr_01f_72a7

    ret nz

    rlca
    inc l
    and c
    ret nc

    rlca
    rst $38
    db $ec
    ld [bc], a
    inc h
    db $f4
    nop
    rlca
    ld [hl+], a
    db $e4
    add b
    ld b, $22
    db $e4
    nop
    rlca
    ld [hl+], a
    db $e4
    ret nz

    rlca
    cpl
    ld a, [c]
    ldh [rTAC], a
    rst $38
    db $ec
    ld [bc], a
    ld [hl+], a
    ld [$0000], sp
    inc h
    call nc, Call_000_0701
    ld [hl+], a
    call nz, Call_000_0681
    ld [hl+], a
    call nz, Call_000_0701
    ld [hl+], a
    call nz, Call_000_07c1
    cpl
    jp nc, Jump_000_07e1

    rst $38
    db $ec
    ld [bc], a
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
    nop
    db $10
    inc d
    inc h
    ld a, [c]
    nop
    ld b, $fe
    inc b
    ld e, [hl]
    ld [hl], e
    cpl
    di
    nop
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
    ld [bc], a
    db $10
    dec d
    cpl
    ldh a, [$f0]
    inc b
    cpl
    ld a, [c]
    ld d, b
    ld b, $10

Call_01f_7393:
    ld [$ecff], sp
    ld [bc], a
    cpl
    ld a, [c]
    ret nz

    rlca
    cpl
    nop
    nop
    nop
    cpl
    nop
    nop
    nop
    inc hl
    add c
    add b
    rlca
    inc hl
    add c
    nop
    rlca
    inc hl
    add c
    ld b, b
    rlca
    inc hl
    add c
    nop
    rlca
    inc hl
    add c
    add b
    rlca
    inc hl
    add c
    nop
    rlca
    inc hl
    add c
    ret nz

    rlca
    inc hl
    add c
    nop
    rlca

Call_01f_73c3:
    rst $38
    db $ec
    ld [bc], a

Call_01f_73c6:
    inc h

Call_01f_73c7:
    ldh a, [rP1]
    ld b, $24
    ldh a, [rP1]
    inc b
    inc h
    ldh a, [rP1]
    ld [bc], a
    ld hl, $0000
    nop
    rst $38
    db $ec
    ld [bc], a
    inc h
    ldh a, [rP1]
    rlca
    inc h
    nop
    nop
    nop
    inc h
    ldh a, [rP1]
    rlca
    ld hl, $0000
    nop
    rst $38
    db $ec
    ld bc, $1710
    cpl
    rst $10
    nop
    ld b, $2f
    or a
    add b
    dec b
    cpl
    add a
    nop
    dec b
    cpl
    ld b, a
    add b
    inc b
    cpl
    rla
    nop
    inc b
    db $10
    ld [$ecff], sp
    ld [bc], a
    inc h
    nop
    nop
    nop
    ld [hl+], a
    pop af
    add b
    ld b, $21
    nop
    nop
    nop
    inc h
    pop af
    add b
    rlca
    inc h
    nop
    nop
    nop
    rst $38
    db $ec
    ld [bc], a
    db $10
    inc l
    inc h
    ld a, [c]
    nop
    dec b
    db $10
    ld [hl+], a
    ld [hl+], a
    pop af
    nop
    dec b
    db $10
    ld [$0021], sp
    nop
    nop
    rst $38
    db $ec
    ld bc, $1710
    cpl
    rst $10
    nop
    dec b
    cpl
    or a
    add b
    dec b
    cpl
    add a
    nop
    ld b, $2f
    ld b, a
    add b
    ld b, $2f
    rla
    nop
    rlca
    db $10
    ld [$ecff], sp
    ld bc, $1710
    cpl
    rst $10
    nop
    rlca
    cpl
    or a
    add b
    ld b, $2f
    add a
    nop
    ld b, $2f
    ld b, a
    add b
    dec b
    cpl
    rla
    nop
    dec b
    db $10
    ld [$ecff], sp
    ld bc, $1610
    cpl
    jp nc, $0500

    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    sub l
    cpl
    ld a, [c]
    nop
    inc b
    db $10
    ld [$22ff], sp
    pop af
    ld [hl-], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    pop af
    ld [hl+], a
    ld hl, $0000
    rst $38
    ld [hl+], a
    pop af
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    and c
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    pop de
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    add c
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    or c
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    ld h, c
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    sub c
    ld [de], a
    ld [hl+], a
    nop
    nop
    ld [hl+], a
    ld b, c
    ld [de], a
    ld [hl+], a
    nop
    nop
    rst $38
    db $ec
    inc bc
    db $10
    ld e, d
    inc h
    ldh a, [rP1]
    dec b
    db $10
    ld [$0024], sp
    nop
    nop
    cpl
    ldh a, [rP1]
    dec b
    ld hl, $0000
    nop
    rst $38
    db $ec
    inc bc
    inc h
    ldh a, [rSB]
    inc b
    inc h
    nop
    nop
    nop
    cpl
    ldh a, [rSB]
    inc b
    ld hl, $0000
    nop
    rst $38
    db $ec

jr_01f_74e6:
    nop
    db $10
    rla
    cpl
    jp nc, $0700

    db $10
    ld [$24ff], sp
    and d
    inc hl
    jr z, jr_01f_74e6

    inc [hl]
    cpl
    nop

jr_01f_74f8:
    nop
    ld [hl+], a
    rst $30
    inc h
    ld [hl+], a
    rst $30
    inc [hl]
    inc h
    rst $30
    ld b, h
    jr z, jr_01f_74f8

    ld d, l
    jr z, jr_01f_74f8

    ld b, h
    rst $38
    db $ec
    ld [bc], a
    cpl
    ldh a, [rP1]
    dec b
    inc h
    nop
    nop
    nop
    cpl
    ldh a, [rP1]
    dec b
    cpl
    ldh a, [rP1]
    dec b
    cpl
    ldh a, [rP1]
    dec b
    cpl
    ldh a, [rP1]
    dec b
    cpl
    ld a, [c]
    nop
    dec b
    rst $38
    db $ec
    inc bc
    cpl
    ldh a, [$82]
    inc b
    inc h
    nop
    nop
    nop
    cpl
    ldh a, [$82]
    inc b
    cpl
    ldh a, [$82]
    inc b
    cpl
    ldh a, [$82]
    inc b

jr_01f_753e:
    cpl
    ldh a, [$82]
    inc b
    cpl
    ld a, [c]
    add d
    inc b
    rst $38
    db $ec
    ld bc, $3a10
    inc h

jr_01f_754c:
    ld a, [c]
    nop
    dec b
    db $10
    ld [hl+], a
    inc h
    ld [c], a
    nop
    dec b
    db $10
    ld a, [hl-]
    inc h
    ld a, [c]
    nop
    rlca
    db $10
    ld [hl+], a
    cpl
    ld [c], a
    nop
    rlca
    db $10
    ld [$26ff], sp
    jr nz, jr_01f_7577

    ld h, $2f
    ld b, b
    ld h, $4f
    ld b, c
    ld h, $8f
    ld b, c
    ld h, $cf
    ld b, d
    jr z, jr_01f_754c

    ld b, d
    cpl

jr_01f_7577:
    rst $20

jr_01f_7578:
    ld b, e
    cpl
    ld a, [c]
    ld b, e
    rst $38
    inc h
    pop de
    ld b, c
    rst $38
    inc h
    pop bc
    ld b, d
    rst $38
    ld [hl+], a
    ld l, a
    ld hl, $af22
    ld sp, $f22f
    ld b, c
    rst $38
    ld [hl+], a

jr_01f_7590:
    jp nc, $2f32

    ld a, [c]

jr_01f_7594:
    ld b, e
    rst $38
    jr z, jr_01f_75d4

    jr nz, jr_01f_75c0

    and b
    jr nz, jr_01f_75c5

    or b
    ld hl, $c02a
    ld [hl+], a
    cpl

jr_01f_75a3:
    jp nc, $ff23

    db $ec
    ld [bc], a
    ld hl, $a0f2
    ld b, $21
    ld a, [c]
    ldh [rTMA], a
    jr z, jr_01f_75a3

    nop
    rlca
    rst $38
    db $ec

Call_01f_75b6:
    ld [bc], a

Call_01f_75b7:
    ld [hl+], a
    pop af
    nop
    rlca
    jr z, jr_01f_753e

    ldh [rTAC], a
    rst $38

jr_01f_75c0:
    db $ec
    inc bc
    dec h
    pop hl
    nop

jr_01f_75c5:
    rlca
    ld [hl+], a

Call_01f_75c7:
    pop hl
    add b
    rlca
    cpl
    pop af
    ret nz

    rlca
    rst $38
    db $ec
    ld [bc], a
    inc h
    pop bc
    pop bc

jr_01f_75d4:
    ld b, $22
    pop bc
    ld b, c
    rlca
    cpl
    pop de
    add c
    rlca
    rst $38
    db $ec
    ld [bc], a
    db $10
    ld e, a
    inc h
    ld b, b
    ldh [rTAC], a
    inc h

Call_01f_75e7:
    ld h, b
    ldh [rTAC], a
    inc h
    add b
    ldh [rTAC], a
    jr z, jr_01f_7590

    ldh [rTAC], a
    jr z, jr_01f_7594

    ldh [rTAC], a
    jr z, jr_01f_7578

    ldh [rTAC], a
    jr z, @+$62

    ldh [rTAC], a
    jr z, jr_01f_7630

    ldh [rTAC], a
    cpl
    ld [de], a
    ldh [rTAC], a
    db $10
    ld [$fcff], sp
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

jr_01f_7630:
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
    jr z, jr_01f_766d

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

jr_01f_765a:
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

jr_01f_766b:
    rst $10
    rlca

jr_01f_766d:
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

jr_01f_76a2:
    jr z, jr_01f_765a

    inc a
    ld h, $d4
    dec a
    jr z, jr_01f_766b

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
    jr z, jr_01f_76a2

    inc l
    rst $38
    db $fc
    ldh a, [$2f]
    rst $30
    add b
    ld b, $2a

jr_01f_76ea:
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

jr_01f_7706:
    db $fc
    dec b
    cpl
    or a
    ld b, c

Call_01f_770b:
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

    jr z, jr_01f_7706

    jr nc, jr_01f_775e

    rst $38
    db $fc
    ld a, [bc]
    inc h

jr_01f_775b:
    ld [$0000], sp

jr_01f_775e:
    ld h, $a7
    ld b, c
    rlca
    jr z, jr_01f_76ea

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

Call_01f_7790:
    rst $38
    db $fc
    and l
    ld h, $f4
    ld b, b
    rlca

jr_01f_7797:
    cpl
    db $e3
    jr nc, jr_01f_77a2

    inc h
    db $f4
    ld b, b
    rlca
    dec h
    or e
    ld c, b

jr_01f_77a2:
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

Call_01f_77b7:
    jp Jump_000_0721


    jr z, @-$4d

    ld [hl-], a
    rlca
    rst $38
    jr z, jr_01f_7797

    inc l
    inc l
    add $3c
    ld a, [hl+]
    or [hl]
    inc l

jr_01f_77c8:
    jr z, jr_01f_775b

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
    jr z, jr_01f_77c8

    add d
    inc b
    rst $38
    inc l
    db $e4
    ld c, h
    ld a, [hl+]
    rst $00

jr_01f_780f:
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

jr_01f_784a:
    ld [bc], a
    ld b, $ff
    inc hl
    db $e4
    inc a
    inc l
    sub $2c
    inc h

jr_01f_7854:
    db $e4
    inc a
    jr z, jr_01f_780f

jr_01f_7858:
    ld e, h
    cpl
    jp nz, $ff5d

    db $fc
    ret


    jr z, jr_01f_7858

    add b
    ld b, $22
    rst $30
    ld h, b
    ld b, $21
    rst $20
    ld b, b
    ld b, $21
    rst $20
    jr nz, jr_01f_7875

    cpl
    pop de
    nop
    ld b, $24
    rst $00

jr_01f_7875:
    ld b, b
    rlca
    inc h
    and a
    jr nc, jr_01f_7882

    cpl
    sub c
    jr nz, @+$09

    rst $38
    db $fc
    ld a, c

jr_01f_7882:
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
    jr jr_01f_78ba

    cpl
    push hl
    sbc b
    rlca
    jr z, jr_01f_784a

    ld e, b

jr_01f_78ba:
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

jr_01f_78c6:
    jr z, jr_01f_7939

    ld c, b
    rlca
    rst $38
    inc hl
    and c
    inc e
    ld l, $94
    inc l
    jr z, jr_01f_7854

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
    jr z, jr_01f_78c6

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

jr_01f_78ff:
    ld h, c
    ld hl, $6128
    ld de, $fcff
    ld a, [$8326]
    ld b, a

jr_01f_790a:
    ld [bc], a
    cpl

jr_01f_790c:
    ld h, d
    ld h, $02

jr_01f_790f:
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
    jr z, jr_01f_790f

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

jr_01f_7939:
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
    jr z, jr_01f_790a

    ld e, h

jr_01f_795a:
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
    jr z, jr_01f_790c

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
    jr z, jr_01f_78ff

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

jr_01f_7999:
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
    jr z, jr_01f_795a

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

jr_01f_79c0:
    ld b, c
    rlca
    inc h
    pop af
    add d
    rlca
    jr z, jr_01f_7999

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
    jr nz, jr_01f_7a00

    ld [hl+], a
    or d
    db $10
    ld b, $22
    and d

jr_01f_7a00:
    jr jr_01f_7a08

    ld [hl+], a
    or d
    db $10
    ld b, $28
    pop bc

jr_01f_7a08:
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

jr_01f_7a2b:
    reti


    dec b
    jr z, jr_01f_79c0

    pop hl
    dec b
    rst $38
    db $ec
    nop
    jr z, jr_01f_7a2b

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

jr_01f_7a68:
    jr nz, jr_01f_7a70

    cp $02
    ld d, b
    ld a, d
    rst $38
    db $fc

jr_01f_7a70:
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

jr_01f_7a9e:
    ld h, $d2
    inc e
    add hl, hl
    or c
    inc l
    jr z, jr_01f_7a68

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

jr_01f_7abe:
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
    jr nz, jr_01f_7ad2

    jr z, jr_01f_7a9e

    db $10
    rlca
    rst $38
    db $fc
    ld e, d

jr_01f_7ad2:
    dec h
    or e
    pop af
    ld b, $27
    push bc
    ld d, d
    rlca

jr_01f_7ada:
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
    jr z, jr_01f_7b5f

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
    jr z, jr_01f_7abe

    and c
    ld b, $26
    add [hl]

jr_01f_7b1b:
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
    jr z, jr_01f_7b1b

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
    jr z, jr_01f_7ada

    inc a
    rst $38
    db $fc
    ldh a, [$2f]
    or $65
    dec b
    ld a, [hl+]

jr_01f_7b52:
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

jr_01f_7b5f:
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

    jr z, jr_01f_7b52

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
    jr nc, jr_01f_7be1

    rst $38
    db $fc
    add c
    ld [hl+], a
    jp nz, Jump_000_0701

jr_01f_7be1:
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

jr_01f_7c02:
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

jr_01f_7c25:
    db $e4
    ldh [rTMA], a
    jr z, @-$2d

    ret nc

    ld b, $ff
    db $fc
    ld a, [bc]
    daa
    and $81

jr_01f_7c32:
    ld b, $2e
    push de
    pop bc
    ld b, $24
    call nz, $06b1
    inc h
    call nc, Call_000_06a1
    jr z, jr_01f_7c02

jr_01f_7c41:
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

jr_01f_7c4d:
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

    jr z, jr_01f_7c32

    add b
    inc b
    rst $38
    db $fc
    xor $2b
    jp nc, Jump_000_0438

    ld l, $c6

jr_01f_7c6c:
    sbc b
    inc b
    inc hl

jr_01f_7c6f:
    or d
    adc b
    inc b
    jr z, jr_01f_7c25

    ld a, b
    inc b
    rst $38
    ld a, [hl+]
    and $6c
    cpl

jr_01f_7c7b:
    jp nc, Jump_000_235c

    jp nz, Jump_000_286c

    pop de
    ld e, h
    rst $38
    db $fc
    inc sp
    cpl
    or $c0

jr_01f_7c89:
    dec b
    jr z, jr_01f_7c6f

    cp h
    dec b
    ld h, $d2
    ret nc

    dec b
    ld h, $b2
    ldh [rTIMA], a
    ld h, $c2
    ldh a, [rTIMA]
    jr z, jr_01f_7c4d

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

jr_01f_7caa:
    or d
    pop bc
    inc b
    jr z, jr_01f_7c41

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

jr_01f_7cbd:
    ld a, [hl+]
    sub $6c
    inc h
    jp nz, $264c

jr_01f_7cc4:
    db $d3
    ld e, h
    jr z, jr_01f_7c7b

    ld c, h
    jr z, jr_01f_7c6c

    ld e, h
    rst $38
    db $fc
    ldh a, [$28]
    db $e4

jr_01f_7cd1:
    sub b
    rlca
    cpl
    push af
    ret nz

    rlca
    jr z, jr_01f_7caa

    ret c

jr_01f_7cda:
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
    jr z, jr_01f_7c89

    or a
    rlca
    rst $38
    jr z, jr_01f_7cd1

    ld c, h
    ld l, $c4
    inc a
    jr z, jr_01f_7cc4

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

jr_01f_7d34:
    ld bc, $2607
    and d
    ld b, d
    rlca

jr_01f_7d3a:
    jr z, jr_01f_7cbd

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

jr_01f_7d53:
    dec de
    dec h
    sub d
    ld a, [de]
    jr z, jr_01f_7cda

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
    jr z, jr_01f_7d3a

    db $10
    rlca
    inc h
    jp nz, $0700

    inc h
    jp nc, Jump_000_06f0

    jr z, jr_01f_7d34

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
    jr z, jr_01f_7d53

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

jr_01f_7de4:
    rlca
    daa
    add $e0
    rlca

jr_01f_7de9:
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

jr_01f_7e0e:
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
    jr z, jr_01f_7de4

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


    jr z, jr_01f_7e0e

jr_01f_7e3d:
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
    jr z, jr_01f_7de9

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
    jr z, jr_01f_7e3d

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
    jr nz, jr_01f_7e8a

    jr z, @-$5d

    inc h
    ld b, $ff
    db $fc

jr_01f_7e8a:
    ld [hl+], a
    cpl
    or b
    jp Jump_000_2a06


    and b
    pop bc
    ld b, $26
    add h

jr_01f_7e95:
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

jr_01f_7ea8:
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

    jr z, jr_01f_7e95

    and b
    ld b, $ff
    db $fc
    rrca
    add hl, hl
    push de
    ld sp, $2306

jr_01f_7ede:
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

jr_01f_7eef:
    sub c
    ld b, $23
    jp nz, $0671

    jr z, jr_01f_7ea8

    ld d, c
    ld b, $ff
    ld h, $e3
    ld c, h
    inc h
    jp $253c


jr_01f_7f01:
    call nc, Call_000_243c
    call nz, Call_000_262c
    or h
    inc a
    jr z, @-$3d

    inc l
    rst $38

jr_01f_7f0d:
    db $fc
    and l
    inc hl
    db $f4
    ld b, c
    ld b, $2d
    sub $21
    rlca
    jr z, jr_01f_7f0d

    add hl, de
    rlca
    jr z, jr_01f_7ede

    ld a, [de]
    rlca
    rst $38
    db $fc
    call z, $f424

jr_01f_7f24:
    add b
    dec b
    ld l, $e6
    ldh [rTMA], a
    jr z, jr_01f_7f01

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
    jr z, jr_01f_7eef

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
    ld de, $2805
    pop de
    ld de, $ff05
    db $fc
    dec d
    inc l
    pop hl
    inc c

jr_01f_7f58:
    dec b
    inc l

jr_01f_7f5a:
    pop de
    db $10
    dec b
    ld l, $c1
    inc c
    dec b
    jr z, jr_01f_7f24

    ld a, [bc]

jr_01f_7f64:
    dec b
    rst $38
    ld l, $f2
    ld h, l
    dec l
    ld [c], a

jr_01f_7f6b:
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

jr_01f_7f77:
    ld h, h
    dec b
    ld [hl+], a
    ld [c], a

jr_01f_7f7b:
    ld b, h
    dec b
    dec h
    pop de
    ld [hl+], a

Call_01f_7f80:
    dec b
    ld [hl+], a
    or d
    add h
    inc b
    jr z, jr_01f_7f58

    and d
    inc b
    inc hl
    di

jr_01f_7f8b:
    inc h
    dec b
    inc h
    db $e4
    db $e4
    inc b
    jr z, jr_01f_7f64

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
    jr z, jr_01f_7f6b

    and b
    inc b
    inc hl
    db $d3
    jr nz, @+$07

    inc hl
    call nz, Call_000_04e0
    jr z, jr_01f_7f77

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

    jr z, jr_01f_7f5a

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
    jr z, jr_01f_7f7b

    ld c, c
    rst $38
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
    jr z, jr_01f_7f8b

    ld c, c
    rst $38
    ld a, [bc]
    add e
    nop
    nop
