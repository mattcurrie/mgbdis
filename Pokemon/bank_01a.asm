; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $01a", ROMX[$4000], BANK[$1a]

    nop
    nop
    nop
    ldh a, [$d9]
    di
    db $db

jr_01a_4007:
    reti


    nop

jr_01a_4009:
    nop
    nop
    inc bc
    rst $08
    ld e, e
    sbc e
    rst $08
    nop
    nop
    nop
    ld a, b
    jp $dbdb


    ld a, e
    nop
    nop
    nop
    nop
    call c, $3935
    inc e
    nop
    nop
    nop
    nop
    xor $ad
    call Call_000_00ed
    nop
    nop
    call z, $cdcc
    ld a, c
    jr nc, jr_01a_4031

jr_01a_4031:
    nop
    nop
    nop
    rst $28
    xor h
    call z, Call_000_00ec
    nop
    nop
    ld bc, $713c
    dec e
    ld a, c
    nop
    nop
    nop
    add b
    inc e
    or [hl]
    or [hl]
    sbc h
    nop
    nop
    nop
    nop
    ldh [$d0], a
    ret nc

    ret nc

    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    ld bc, $36fe
    ld a, [$f14e]
    cpl
    db $f4
    rra
    ld [c], a
    dec sp
    ldh [$7f], a
    sbc h
    sbc [hl]
    and d
    jr jr_01a_4083

jr_01a_4083:
    ld h, [hl]
    jr jr_01a_4007

    jr jr_01a_4009

    nop
    ld h, [hl]
    ld h, [hl]
    sbc c
    adc b
    ld [hl], a
    ld b, c
    jr jr_01a_4091

jr_01a_4091:
    rst $38
    nop
    nop
    rst $38
    rst $38
    inc a
    rst $20
    ld a, $e5
    ld h, [hl]
    and l
    ld h, h
    and l
    nop
    sbc b
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
    nop
    rst $38
    nop
    nop
    rst $38
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
    rlca
    ei
    dec de
    and $20
    push bc
    ld b, b
    jp $8f44


    add b
    sbc a
    add b
    rst $28
    add b
    rst $38
    ldh [rIE], a
    cp b
    sbc a
    inc a
    rst $10
    ld a, $8f
    ld a, d
    ld d, a
    cp l
    sbc a
    ld a, e
    rst $38
    dec [hl]
    nop
    rst $38
    nop
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    nop
    rst $38
    ld [bc], a
    ld bc, $01fe
    cp $01
    cp $01
    cp $01
    cp $01
    cp $01

Jump_01a_4100:
    rst $38
    nop
    rst $38
    inc bc
    db $fc
    rrca
    db $10
    rst $38
    ldh [$3f], a
    db $e3
    ccf
    db $e4
    ccf
    jr c, @+$01

    rst $38
    nop
    rst $38
    add b
    ld a, a
    ldh [rNR10], a
    rst $38
    rrca
    ld hl, sp-$71
    ld hl, sp+$4f
    ld hl, sp+$38
    rst $38
    cp a
    ret nz

    cp a
    rst $38
    cp a
    push hl
    cp l
    push hl
    and l
    push hl
    cp a
    db $fd
    cp a
    rst $38
    cp a
    ret nz

    db $fd
    inc bc
    db $fd
    rst $38
    db $fd
    daa
    dec h
    daa
    dec h
    daa
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    inc bc
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
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
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
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    xor e
    sbc e
    call nc, $f37f
    ccf
    ldh a, [$38]
    ret c

    ld a, b
    db $ec
    cp h
    db $e3
    cp a
    db $e3
    xor e
    db $d3
    reti


    dec hl
    cp $cf
    db $fc
    rrca
    inc e
    dec de
    ld e, $37
    dec a
    rst $00
    db $fd
    rst $00
    push de
    nop
    inc a
    nop
    adc c
    nop
    ld h, b
    nop
    rst $30
    nop
    rst $20
    nop
    rst $20
    nop
    sbc e
    nop
    call c, $ff00
    xor d
    nop
    rst $10
    nop
    xor e
    nop
    nop
    rst $38
    db $eb
    nop
    rst $30
    nop
    db $eb
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
    nop
    nop
    rst $38

Jump_01a_41be:
    rst $38
    nop
    push de
    add [hl]
    ld hl, sp-$1f
    push af
    db $d3
    reti


    adc a
    db $e3
    sbc c
    ei
    or [hl]
    ld a, e
    rst $28
    ccf
    sub $7f
    db $eb
    dec d
    sub a
    xor a
    set 2, a
    xor l
    adc e
    ld d, a
    sub a
    db $eb
    rst $00
    ld a, l
    rst $38
    ld a, d
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ld a, a
    add b
    nop
    rst $38
    cp $01
    cp $01
    cp $01
    cp $01
    cp $01
    cp $01
    cp $01
    nop
    rst $38
    db $ec
    cpl
    db $e3
    inc hl
    ldh [$30], a
    db $10
    db $fc
    ret nc

    inc sp
    db $ec
    inc e
    di
    rrca
    nop
    rst $38
    ld l, a
    add sp, -$71
    adc b
    rrca
    jr jr_01a_4227

    ld a, a
    rla
    sbc b
    ld l, a
    ld [hl], b
    sbc a
    ldh [rP1], a
    rst $38
    cp a
    rst $38
    cp a
    pop bc
    cp a
    pop bc
    cp a

jr_01a_4227:
    pop bc
    cp a
    pop bc
    rst $38
    rst $38
    cp a
    ret nz

    rst $38
    ld a, a
    db $fd
    rst $38
    db $fd
    add e
    db $fd
    add e
    db $fd
    add e
    db $fd
    add e
    rst $38
    rst $38
    db $fd
    inc bc
    rst $38
    cp $ff
    nop
    rst $38
    nop
    rst $38
    nop
    db $10
    rst $28
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
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    add b
    rst $38
    rst $38
    push bc
    cp d
    cp a
    rst $38
    or l
    ld [$00ff], a
    rst $38
    rst $38
    rst $38
    ld bc, $01ff
    rst $38
    rst $38
    ld bc, $fdff
    rst $38
    dec b
    rst $38
    rst $38
    sbc a
    rst $38
    add a
    cp a
    ret nz

    sbc a
    and b
    add b
    sbc a
    sbc a
    add b
    sbc a
    rst $08
    sbc d
    xor l
    rst $38
    ld sp, hl
    rst $38
    pop hl
    db $fd
    inc bc
    ld sp, hl
    rlca
    ld bc, $f9ff
    rlca
    ld sp, hl
    rst $30
    reti


    scf
    rst $38
    rst $38
    add b
    add b
    cp a
    cp a

jr_01a_4296:
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    rst $38
    rst $38
    nop
    nop
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
    ld bc, $fd01
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
    rst $38
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
    rst $38
    nop
    nop
    nop

jr_01a_42df:
    nop
    rst $38
    ld a, a
    add b
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    rst $38
    cp $01
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $8a20
    db $10
    dec b
    ld [$5000], sp
    ld bc, $8a20
    inc b
    db $10
    jr nz, jr_01a_4296

    nop

jr_01a_430f:
    ld d, c
    xor e
    inc bc
    ld e, l
    inc e
    cp [hl]
    ld l, b
    ld a, l
    jr nz, jr_01a_430f

    ld e, h
    ld e, l
    ld l, e
    ld [$d575], a
    xor e
    xor d
    add b
    ld [hl], l
    ld [hl], b
    xor d
    jr c, jr_01a_4384

    jr z, jr_01a_42df

    ld e, h
    ld b, l
    db $fc
    xor h
    ld a, [hl]
    ld d, a
    cp $c2
    rst $38
    or b
    rst $38
    ld l, d
    rst $38
    ld d, a
    ld a, a
    cp e
    ccf
    ld e, [hl]
    ccf
    and l
    ld e, $53
    rrca
    xor d
    cp $53
    cp $ae
    db $fc
    ld [hl], l
    db $fc
    ld a, [$75fc]
    ld hl, sp-$60
    ld a, d
    push bc
    ldh a, [$aa]
    push af
    and h
    ei
    cp a
    rst $38
    and l
    ld a, [$f5aa]
    cp a
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    add l
    ld a, a
    dec b
    rst $38
    db $fd
    rst $38
    and l
    ld e, a
    dec b
    rst $38
    db $fd
    rst $38
    ld bc, $ffff
    rst $38
    adc b
    sbc a
    sbc e
    adc h
    sbc b
    adc a
    sbc a
    adc a
    sbc a
    add b
    rst $18
    ld b, b
    rst $38
    jr nz, @+$01

    rra
    ld de, $d9ff
    scf

jr_01a_4384:
    add hl, de
    rst $30
    ld sp, hl
    rst $30
    ld sp, hl
    rlca
    ei
    ld b, $ff
    inc b
    rst $38
    ld hl, sp+$7f
    ld a, a
    ld c, a
    ld [hl], b
    ld h, b
    ld h, b
    jr nz, jr_01a_43c3

    jr nz, jr_01a_43ba

    jr nz, jr_01a_43c9

    jr nz, jr_01a_43c9

    jr nz, jr_01a_43c0

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
    cp a
    xor a
    or a
    xor b
    sbc a
    cp a
    and b
    and b
    and b
    cp a

jr_01a_43ba:
    and b
    or d
    or b
    db $ed
    rst $38
    rst $38

jr_01a_43c0:
    rst $38
    or $ee

jr_01a_43c3:
    rla
    ld sp, hl
    rst $38
    dec c
    ld b, $05

jr_01a_43c9:
    cp $05
    xor [hl]
    inc b
    ld e, a
    rst $38
    rst $38
    rst $38
    add b
    ld a, a
    ld l, h
    ld d, a
    ld a, d
    adc a
    db $f4
    cpl
    ld hl, sp+$47
    call c, $fe07
    cp c
    ld a, c
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
    rst $38
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
    rst $38
    rst $38
    rst $38
    rst $38
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
    rst $38
    nop
    rst $38
    nop
    add b
    nop
    add b
    nop
    add b
    ld bc, $0380
    add b
    rlca
    add b
    ld c, $80
    inc e
    rst $38
    nop
    ld bc, $0100
    nop
    ld bc, $0180
    ret nz

    ld bc, $01e0
    ld [hl], b
    ld bc, $5538
    ld bc, $01ab
    ld d, l
    ld bc, $01ab

jr_01a_4438:
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $ffff
    rst $38
    nop
    add c
    nop
    add c
    inc a
    nop
    cp l
    add c
    inc a
    add c
    inc a
    add c
    nop
    nop
    rst $38
    xor d
    nop
    ld b, c
    inc d
    xor b
    ld l, d
    ld d, l
    ld a, h
    add d
    cp $57
    ld a, a
    rst $28
    rst $38
    ld e, l
    ld a, a
    xor d
    jr z, jr_01a_4438

    db $fc
    and d
    cp $55
    rst $38
    ld a, [$55fe]
    db $fc
    db $ec
    ld a, [hl]
    cp l
    ld e, b
    push de
    add b
    xor d
    add b
    push de
    add b
    xor d
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    rst $38
    cp $fe
    ld a, [c]
    ld c, $06
    ld b, $04
    ld d, h
    inc b
    ld d, h
    inc b
    ld b, h
    inc b
    ld [hl], h
    inc b
    ld b, h
    add b
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
    nop
    rst $38
    inc bc
    inc bc
    inc b
    inc b
    ld [$0809], sp
    dec bc
    ld [$0409], sp
    inc b
    inc bc
    inc bc
    nop
    rst $38
    ret nz

    ret nz

    jr nz, jr_01a_44d6

    db $10
    sub b
    db $10
    ret nc

    db $10
    sub b
    jr nz, jr_01a_44de

    ret nz

    ret nz

    ld bc, $01ff
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $00ff
    rst $38
    nop
    rst $38
    nop

jr_01a_44d6:
    ld bc, $ffff
    rlca
    rst $38
    dec e
    rst $38
    dec d

jr_01a_44de:
    rra
    rst $38
    rst $38
    rlca
    rst $38
    dec e
    rst $38
    ld [hl], l
    rst $18
    rst $38
    pop af
    ld d, c
    pop af
    pop af
    ld de, $1711
    rla
    pop af
    ld de, $f1f1
    sub c
    pop af
    sub a
    rst $30
    sbc l
    db $fd
    sub l
    push af
    sbc a
    rst $38
    rst $38
    rst $38
    dec e
    dec e
    ld [hl], l
    ld [hl], l
    rst $18
    rst $18
    ld d, c
    ld e, a
    pop af
    rst $38
    ld bc, $01ff
    rst $38
    rst $38
    rst $38
    add b
    inc e
    add b
    ld c, $80
    rlca
    add b
    inc bc
    add b
    ld bc, $0080
    add b
    nop
    rst $38
    nop
    ld bc, $0138
    ld [hl], b
    ld bc, $01e0
    ret nz

    ld bc, $0180
    nop
    ld bc, $ff00
    nop
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b

jr_01a_4540:
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    xor h
    cpl
    ld b, d
    rla
    xor d
    ld b, d
    ld d, [hl]
    ld [bc], a
    and l
    inc c
    ld e, d
    inc c
    and [hl]
    rrca
    ld d, c
    rlca
    ld a, [hl+]
    ldh [rHDMA5], a
    ret nz

    ld [$d540], a
    ld b, b
    ld l, d
    jr nc, jr_01a_4540

    jr c, jr_01a_45d5

    ld a, [c]
    sub l
    ldh [$60], a
    cpl
    and b
    inc h
    ld h, b
    dec hl
    ldh [$60], a
    ret nz

    ld a, a
    rst $38
    ld a, a
    rst $38
    nop
    rst $38
    rst $38
    dec b
    ld h, h
    ld b, $34
    dec b
    sub h
    ld b, $06
    inc bc
    cp $ff
    cp $ff
    nop
    rst $38
    rst $38
    add b
    add b
    add b
    add b
    cp a
    cp a
    ret nz

    ret nc

    cp a
    cp a
    rst $38
    adc h
    add b
    add b
    rst $38
    rst $38
    ld l, a
    sub a
    dec b
    rst $38
    ld sp, hl
    rst $38
    push bc
    ld d, a
    rst $00
    ld a, [hl]
    rst $38
    ld b, h
    jr c, @+$01

    rst $38
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    inc h
    rst $38
    rst $38
    rst $38
    jr jr_01a_45bd

jr_01a_45bd:
    nop
    rst $38
    rst $38
    ld bc, $0101
    ld bc, $fdfd
    inc bc
    dec bc
    db $fd
    db $fd
    rst $38
    ld sp, $0101
    rst $38
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    rst $38

jr_01a_45d5:
    rst $38
    jp $c37f


    ld a, a
    cp h
    ld a, a
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    ld bc, $ffff
    rst $38
    jp $c3fe


    cp $3f
    db $fc
    rst $38
    nop
    rst $38
    nop
    rra
    rra
    ld h, b
    ld h, b
    and b
    and b
    cp a
    and b
    cp a
    xor a
    cp b
    xor h
    cp b
    xor a
    cp b
    xor h
    ld sp, hl
    ld sp, hl
    ld b, $06
    ld b, $06
    cp $06
    rst $38
    or $1f
    or $1e
    rst $30
    rra
    ld [hl], $f8
    ld hl, sp+$07
    rlca
    inc b
    inc b
    rlca
    inc b
    rst $38
    inc b
    db $fc
    rst $30
    inc b
    cp $6e
    sub [hl]
    nop
    nop
    cp $fe
    ld bc, $fd01
    inc bc
    db $fd
    inc bc
    dec b
    ei
    dec b
    dec bc
    push hl
    dec bc
    dec b
    dec bc
    and l
    dec bc
    dec b
    dec bc
    dec b
    ei
    db $fd
    inc bc
    db $fd
    inc bc
    ld bc, $ffff
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
    nop
    nop
    nop
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    ld de, $1111
    ld de, $1111
    ld de, $1411
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld de, $1111
    ld de, $1111
    ld de, $0611
    ld b, $06
    ld b, $16
    ld d, $16
    ld d, $11
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0211
    jr c, @+$09

    ld [$1312], sp
    rla
    jr @+$13

    ld de, $1111
    ld de, $1111
    ld de, $0807
    ld [bc], a
    jr c, @+$19

    jr @+$14

    inc de
    rlca
    ld [$0807], sp
    rla
    jr @+$19

    jr @+$09

    ld [$1111], sp
    rla
    jr @+$13

    ld de, $0807
    rlca
    ld [$1817], sp
    rla
    jr @+$13

    ld de, $0807
    ld de, $1711
    jr @+$09

    ld [$0807], sp
    rla
    jr @+$19

    jr @+$13

    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    rlca
    ld [$0807], sp
    rla
    jr @+$19

    jr @+$09

    ld [$1111], sp
    rla
    jr @+$13

    ld de, $0807
    rlca
    ld [$1817], sp
    rla
    jr @+$13

    ld de, $0807
    ld de, $1711
    jr @+$09

    ld [$0807], sp
    rla
    jr jr_01a_4746

    jr @+$09

    ld [$1111], sp
    rla
    jr @+$13

    ld de, $0807
    ld de, $1711
    jr @+$13

    ld de, $1111
    rlca
    ld [$1111], sp

jr_01a_4746:
    rla
    jr @+$13

    ld de, $0807
    ld de, $1711
    jr @+$24

    inc hl
    ld de, $3211
    inc sp
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld [hl+], a
    inc hl
    ld de, $3211
    inc sp
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0807
    ld de, $1711
    jr @+$13

    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0711
    ld [$1111], sp
    rla
    jr jr_01a_4796

    dec b
    dec b
    dec b
    db $10
    db $10

jr_01a_4796:
    db $10
    db $10
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    add hl, bc
    ld a, [bc]
    inc d
    inc d
    add hl, de
    ld a, [de]
    inc d
    inc d
    add hl, bc
    ld a, [bc]
    inc d
    inc d
    add hl, de
    ld a, [de]
    inc d
    inc d
    inc d
    inc d
    add hl, bc
    ld a, [bc]
    inc d
    inc d
    add hl, de
    ld a, [de]
    inc d
    inc d
    add hl, bc
    ld a, [bc]
    inc d
    inc d
    add hl, de
    ld a, [de]
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld [bc], a
    jr c, @+$03

    ld bc, $1312
    ld de, $2211
    inc hl
    ld de, $3211
    inc sp
    ld de, $1411
    inc d
    ld [bc], a
    jr c, jr_01a_4809

    inc d
    ld [de], a
    inc de
    inc d
    inc d
    ld [hl+], a
    inc hl
    inc d
    inc d
    ld [hl-], a
    inc sp
    ld de, $1111
    ld de, $1111
    ld de, $0411

jr_01a_4809:
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    ld de, $0411
    inc b
    ld de, $1411
    inc d
    ld de, $1411
    inc d
    ld de, $1411
    inc d
    inc b
    inc b
    ld de, $1411
    inc d
    ld de, $1411
    inc d
    ld de, $1411
    inc d
    ld de, $0411
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    ld bc, $0101
    ld bc, $1111
    ld de, $0411
    inc b
    ld de, $1411
    inc d
    ld de, $0111
    ld bc, $1111
    ld de, $1111
    ld de, $0404
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld bc, $0101
    ld bc, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1414
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld bc, $0101
    ld bc, $1111
    ld de, $2011
    ld hl, $2120
    jr nc, jr_01a_48c7

    jr nc, @+$33

    ld de, $1111
    ld de, $1111
    ld de, $4511
    ld b, [hl]
    dec b
    dec b
    ld d, [hl]
    ld d, [hl]
    ld d, [hl]
    ld d, [hl]
    ld de, $1111
    ld de, $1111
    ld de, $4511
    ld b, [hl]
    add hl, hl
    ld a, [hl+]
    ld d, [hl]
    ld d, [hl]
    dec c
    ld c, $0b
    inc c
    dec c
    ld c, $1b
    inc e
    dec e
    ld e, $11
    ld de, $1111
    ld de, $1111

jr_01a_48c7:
    ld de, $1111
    dec bc
    inc c
    ld de, $1b11
    inc e
    ld de, $1111
    ld de, $1111
    ld de, $0211
    jr c, @+$13

    ld de, $1312
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld [bc], a
    jr c, jr_01a_48fe

    ld de, $1312
    inc h
    ld h, $26
    ld h, $25
    rrca
    rrca
    rrca
    ld b, h
    dec b
    ld b, l
    ld b, [hl]
    ld d, h
    ld d, [hl]

jr_01a_48fe:
    ld d, [hl]
    ld d, [hl]
    ld h, $26
    ld h, $27
    rrca
    rrca
    rrca
    dec [hl]
    ld b, l
    ld b, [hl]
    dec b
    ld b, a
    ld d, [hl]
    ld d, [hl]
    ld d, [hl]
    ld d, a
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1f1f
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld de, $1f11
    rra
    ld de, $1f11
    rra
    ld de, $1f11
    rra
    ld de, $1111
    ld de, $1f1f
    ld de, $1f11
    rra
    ld de, $1f11
    rra
    ld de, $1f11
    rra
    ld [bc], a
    jr c, jr_01a_4974

    ld de, $1312
    ld de, $2211
    inc hl
    ld de, $3211
    inc sp
    ld de, $1111
    ld de, $3802

jr_01a_4974:
    ld de, $1211
    inc de
    ld de, $2211
    inc hl
    ld de, $3211
    inc sp
    inc bc
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    inc bc
    dec hl
    inc bc
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    inc bc
    dec hl
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    dec hl
    dec hl
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    ld e, b
    ld e, c
    ld e, c
    ld e, d
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    dec hl
    dec hl
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    dec hl
    dec hl
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    ld b, b
    ld b, c
    dec hl
    dec hl
    ld d, b
    ld d, c
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    dec hl
    dec hl
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    dec hl
    dec hl
    ld b, b
    ld b, c
    dec hl
    dec hl
    ld d, b
    ld d, c
    dec hl
    dec hl
    inc l
    dec l
    dec hl
    dec hl
    ld l, $2f
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    inc l
    dec l
    ld b, b
    ld b, c
    ld l, $2f
    ld d, b
    ld d, c
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $3f3f
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $3c3c
    ld de, $4c11
    ld c, h
    ld de, $3c11
    inc a
    ld de, $4c11
    ld c, h
    ld de, $1111
    ld de, $1111
    ld de, $3c11
    dec a
    inc a
    dec a
    inc a
    dec a
    inc a
    dec a
    inc h
    ld h, $26
    daa
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    dec h
    rrca
    rrca
    dec [hl]
    ld b, d
    db $10
    db $10
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $2624
    ld h, $27
    ld b, d
    db $10
    db $10
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $3f3f
    inc a
    dec a
    ccf
    ccf
    inc a
    dec a
    inc h
    ld h, $26
    daa
    ld b, d
    db $10
    db $10
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $2724
    dec b
    dec b
    dec h
    dec [hl]
    db $10
    db $10
    dec h
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $0511
    dec b
    inc h
    daa
    db $10
    db $10
    dec h
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    inc h
    daa
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $1111
    ld de, $2724
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    inc h
    ld h, $26
    daa
    ld b, d
    db $10
    dec h
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $1111
    ld de, $1111
    ld de, $2411
    ld h, $26
    daa
    ld b, d
    db $10
    dec h
    dec [hl]
    ld de, $2411
    daa
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    inc h
    daa
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $4211
    ld a, $11
    ld de, $1111
    inc h
    daa
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $4211
    ld a, $24
    daa
    ld de, $2511
    dec [hl]
    ld de, $2511
    rrca
    ld h, $27
    ld b, d
    db $10
    db $10
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $1111
    inc h
    daa
    ld de, $2511
    dec [hl]
    dec h
    dec [hl]
    ld de, $4211
    ld a, $11
    ld de, $1111
    inc h
    daa
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $4211
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    inc h
    ld h, $26
    daa
    dec h
    dec [hl]
    db $10
    ld a, $3d
    dec a
    ld de, $4d11
    ld c, l
    ld de, $2411
    ld h, $26
    daa
    ld b, d
    db $10
    db $10
    ld a, $11
    ld de, $2624
    ld de, $4211
    db $10
    ccf
    ccf
    dec a
    dec a
    ccf
    ccf
    ld c, l
    ld c, l
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    inc h
    ld h, $26
    daa
    ld b, d
    db $10
    db $10
    ld a, $24
    ld h, $26
    daa
    ld b, d
    db $10
    db $10
    ld a, $11
    ld de, $3f3f
    ld de, $3f11
    ccf
    ld h, $27
    ld de, $1011
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld c, h
    ld c, l
    ccf
    ccf
    ld c, h
    ld c, l
    ccf
    ccf
    ld de, $1111
    ld de, $1111
    ld de, $0511
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    ld de, $3c11
    inc a
    ld de, $4c11
    ld c, h
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    inc h
    ld h, $26
    daa
    ld b, d
    db $10
    dec h
    dec [hl]
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    ld c, h
    ld c, l
    inc h
    daa
    ld c, h
    ld c, l
    dec h
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $4211
    ld a, $11
    ld de, $1111
    ld de, $1111
    ld de, $3f3f
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    ld de, $3f11
    ccf
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    dec a
    dec a
    ld de, $4d11
    ld c, l
    ld de, $2411
    daa
    ld de, $2511
    dec [hl]
    ld de, $1111
    ld de, $1111
    ld de, $2611
    daa
    ld de, $1011
    ld a, $11
    ld de, $0505
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    ld e, e
    ld e, h
    ld e, l
    ld e, [hl]
    ld [hl], $37
    ld d, l
    ld e, a
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    add hl, hl
    dec sp
    dec sp
    ld a, [hl+]
    ld c, [hl]
    add hl, sp
    add hl, sp
    ld c, a
    inc [hl]
    ld b, e
    inc [hl]
    ld b, e
    ld d, d
    ld d, e
    ld d, d
    ld d, e
    ld de, $1111
    ld de, $1111
    ld de, $2911
    ld a, [hl+]
    add hl, hl
    ld a, [hl+]
    dec c
    ld c, $0d
    ld c, $0d
    ld c, $0d
    ld c, $1d
    ld e, $1d
    ld e, $11
    ld de, $1111
    ld de, $1111
    ld de, $3b29
    dec sp
    dec sp
    ld c, [hl]
    add hl, sp
    add hl, sp
    add hl, sp
    ld de, $1111
    ld de, $1111
    ld de, $3b11
    ld a, [hl+]
    ld de, $3911
    ld c, a
    ld de, $5811
    ld e, c
    ld e, c
    ld e, d
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld b, $06
    ld b, $06
    ld d, $16
    ld d, $16
    ld e, b
    ld e, c
    ld e, c
    ld e, c
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld e, c
    ld e, d
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $2724
    ld de, $2511
    dec [hl]
    inc h
    ld h, $0f
    dec [hl]
    ld b, d
    db $10
    db $10
    ld a, $48
    ld c, c
    inc h
    daa
    ld c, d
    ld c, e
    dec h
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $2511
    dec [hl]
    ld de, $1111
    ld de, $1111
    ld de, $2411
    daa
    ld de, $2511
    dec [hl]
    ld de, $0211
    jr c, jr_01a_4d93

    ld hl, $1312
    jr nc, jr_01a_4da9

    ld [hl+], a
    inc hl
    ld de, $3211
    inc sp
    ld de, $2011
    ld hl, $3802
    jr nc, jr_01a_4db7

    ld [de], a
    inc de
    ld de, $2211
    inc hl
    ld de, $3211
    inc sp
    rst $38
    rst $38
    rst $38

jr_01a_4d93:
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
    adc b
    nop
    ld b, h
    nop
    ld [hl+], a
    nop
    ld de, $0800

jr_01a_4da9:
    nop
    inc b
    nop
    jp nz, Jump_01a_4100

    nop
    nop
    rst $38
    nop
    add b
    inc bc
    add e
    db $fc

jr_01a_4db7:
    add [hl]
    ld a, b
    adc [hl]
    ld [$788f], sp
    adc b
    db $fc
    add h
    nop
    rst $38
    nop
    ld bc, $c1c0
    ccf
    ld h, c
    ld e, $71
    db $10
    pop af
    ld e, $11
    ccf
    ld hl, $ffff
    add b
    add b
    rst $38
    rst $38
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    rst $38
    ld bc, $ff01
    rst $38
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    add b
    add b
    rst $38
    add b
    rst $38
    rst $38
    cp a
    ld b, b
    cp [hl]
    pop bc
    ld a, l
    ld a, d
    rlca
    ld c, h
    rlca
    ld c, h
    ld b, $7d
    dec b
    ld d, [hl]
    rlca
    ld a, h
    rst $38
    rst $38
    nop
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    nop
    sbc a
    rst $38
    ldh [$ea], a
    or b
    xor a
    and b
    xor d
    cp a
    and b
    cp a
    rst $38
    add b
    rst $38
    rst $38
    ld a, a
    rst $38
    rst $38
    nop
    nop
    inc e
    rst $38
    ld [hl], $f7
    ld e, l
    db $dd
    db $e3
    ld b, c
    ld a, $e3
    rst $38
    inc e
    ld [hl+], a
    nop
    ld b, h
    nop
    adc b
    nop
    stop
    jr nz, jr_01a_4e4a

jr_01a_4e4a:
    ld b, b
    nop
    add a
    nop
    inc b
    nop
    nop
    nop
    nop
    rst $38
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
    rlca
    ld d, h
    rlca
    ld [hl], h
    dec b
    ld d, [hl]
    ld b, $7d
    add a
    call nc, $fc7f
    dec b
    cp $fe
    db $fd
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    sbc a
    and b
    cp d
    and b
    xor a
    and b
    xor d
    db $fd
    ld h, e
    sbc l
    db $d3
    xor l
    db $eb
    or l
    or a
    db $dd
    rst $10
    xor l
    and a
    xor l
    cp e
    cp l
    cp e
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    ld b, b
    nop
    ld b, c
    nop
    jp nz, Jump_000_0400

    nop
    ld [$1100], sp
    nop
    ld [hl+], a
    nop
    ld b, h
    nop
    inc bc
    add e
    nop
    add b
    inc a
    cp h
    cp h
    cp h
    jr nc, @-$4e

    nop
    add b
    nop
    rst $38
    rst $38
    rst $38
    ret nz

    pop bc
    nop
    ld bc, $3d3c
    add hl, sp
    add hl, sp
    inc a
    dec a
    nop
    ld bc, $ff00
    rst $38
    rst $38
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    rst $38
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    rst $38
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
    ld bc, $ff01
    ld bc, $ffff
    or e
    or a
    and c
    cp a
    cp a
    cp a
    add b
    add b
    rst $38
    add b
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    ld a, a
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    rst $38
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    rst $38
    cp a
    ld b, b
    cp [hl]
    ld b, c
    dec a
    jp nz, $04fb

    rst $30
    ld [$11ee], sp
    db $dd
    ld [hl+], a
    cp e
    ld b, h
    inc b
    nop
    inc b
    nop
    add a
    nop
    ld b, b
    nop
    jr nz, jr_01a_4f4a

jr_01a_4f4a:
    stop
    adc b
    nop
    ld b, h
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
    nop
    nop
    rst $38
    nop
    nop
    call $85dd
    db $fd
    db $fd
    db $fd
    ld bc, $ff01
    ld bc, $ffff
    ld bc, $ffff
    cp $a0
    xor d
    and b
    cp a
    and d
    xor b
    cp a
    cp a
    and b
    cp a
    cp a
    cp a
    and b
    cp a
    cp a
    cp a
    adc l
    cp e
    cp l
    adc e
    adc l
    ei
    adc l
    ei
    dec c
    ei
    db $fd
    ei
    dec c
    ei
    db $fd
    ei
    xor b
    jr nz, jr_01a_4fef

    ld e, b
    ld l, [hl]
    ld h, [hl]
    rst $00
    sub l
    ld h, e
    ld l, l
    ret nc

    adc a
    ld h, a
    ld a, a
    rst $38
    ld sp, hl
    ld h, $04
    ld e, [hl]
    ld a, [de]
    db $eb
    ld h, e
    pop af
    and l
    ld b, [hl]
    xor [hl]
    sbc a
    pop af
    or $ce
    sbc b
    ld hl, sp-$77
    ld bc, $0044
    ld [hl+], a
    inc bc
    rra
    ld c, $14
    ld e, $0e
    dec c
    inc a
    ld l, $3e
    cpl
    ld h, d
    ret nz

    call nz, $4840
    ret nz

    ldh a, [rSVBK]
    xor b
    ld a, b
    ld [hl], b
    or b
    cp h
    ld [hl], h
    ld a, h
    db $f4
    ld a, [$d578]
    add h
    rst $28
    add l
    rst $30
    add a
    rst $28
    add a
    rst $30
    add a
    add a
    rst $38
    rst $30
    add a
    cp [hl]
    ld a, $ff
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld sp, hl
    ld sp, hl
    ldh a, [$f0]
    sub d
    sub d
    add b

jr_01a_4fef:
    sub b
    db $ed
    add [hl]
    push af
    add [hl]
    db $ec
    add a
    push af
    add [hl]
    db $ed
    add [hl]
    push af
    add [hl]
    db $fd
    cp $85
    cp $fd
    ld bc, $01fb
    ld bc, $fbff
    ld bc, $01fd
    ei
    ld bc, $01fd
    ei
    ld bc, $00ff
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    add l
    cp $85
    cp $85
    cp $87
    rst $38
    ld hl, sp-$01
    add b
    rst $38
    add b
    rst $38
    ld a, a
    rst $38
    db $fd
    ld bc, $01fb
    db $fd
    ld bc, $ffff
    ld bc, $01ff
    rst $38
    ld bc, $feff
    rst $38
    add b
    add b
    cp a
    rst $38
    and b
    cp [hl]
    and b
    cp h
    cp b
    and b
    or c
    or c
    and d
    and d
    and b
    and l
    ld bc, $fd01
    rst $38
    dec h
    dec l
    dec b
    ld e, l
    cp l
    dec h
    ld a, l
    dec a
    db $fd
    db $fd
    dec b
    db $fd
    xor e
    xor e
    and h
    or a
    xor h
    and a
    cp a
    and h
    cp a
    and a
    cp a
    cp a
    and b
    cp a
    cp a
    cp a
    db $fd
    db $fd
    adc a
    rst $38
    pop af
    sub c
    rst $38
    sub l
    rst $38
    sub l
    rst $18
    pop de
    rrca
    xor a
    ld b, l
    ld b, l
    ld sp, hl
    ld h, [hl]
    pop de
    sub [hl]
    ld h, e
    ld c, d
    push bc
    sub e
    db $eb
    rst $08
    rst $38
    sbc e
    ld [hl], l
    ld e, a
    ld a, a
    dec hl
    sbc $66
    dec c
    reti


    and d
    jp z, $d581

    db $db
    rst $30
    rst $38
    reti


    xor $fa
    ld d, h
    ld d, h
    cpl
    scf
    daa
    jr c, @+$13

    inc e
    rla
    ccf
    inc de
    inc a
    add hl, bc
    inc a
    daa
    rra
    ld b, b
    rlca
    db $f4
    db $ec
    db $e4
    inc e
    ld [$e8f8], sp
    db $fc
    ld [$10fc], sp
    db $fc
    ldh [$f8], a
    inc d
    ldh [$ed], a
    add a
    push af
    add [hl]
    db $ec
    add a
    push af
    add [hl]
    db $ed
    add [hl]
    push af
    add [hl]
    add l
    cp $f5
    add [hl]
    add b
    add b
    pop hl
    ld [hl], e
    ld c, a
    rst $08
    adc a
    adc a
    sbc l
    sbc a
    ld a, [c]
    ld a, a
    db $fc
    rra
    ei
    inc bc
    ld [hl], a
    adc b
    cp e
    ld b, h
    db $dd
    ld [hl+], a
    xor $11
    rst $30
    ld [$04fb], sp
    dec a
    jp nz, Jump_01a_41be

    or a
    ld h, c
    xor a
    ld h, c
    or a
    ld h, c
    xor a
    ld h, c
    or a
    ld h, c
    xor a
    ld h, c
    cp a
    ld a, a
    and c
    ld a, a
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38

jr_01a_5116:
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
    adc b
    nop
    ld b, h
    nop
    and d
    add b
    pop de
    ret nz

    ret z

    ret nz

    add h
    add b
    jp nz, $c180

    add b
    rst $38
    nop
    rra
    rst $38
    jr nz, jr_01a_5116

    ldh [$e0], a
    rst $38
    jr nz, jr_01a_517a

    rst $28
    ld hl, sp-$18
    cp e
    xor b
    rst $38
    nop
    ld hl, sp-$01
    inc b
    rlca
    rlca
    rlca
    db $fc
    rlca
    db $fc
    rst $30
    rra
    rla
    rst $38
    dec d
    cp a
    ret nz

    cp [hl]
    ld b, c
    dec a
    jp nz, $04fb

    rst $30
    adc b
    ld l, [hl]
    pop de
    db $dd
    and d
    cp e
    ld b, h
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
    xor b
    cp [hl]
    cp l
    xor b
    cp d
    xor b
    or h
    and b
    xor b
    xor b

jr_01a_517a:
    cp a
    rst $38
    add b
    add b
    rst $38
    ld a, a
    add l
    adc l
    dec e
    dec b
    dec a
    dec b
    ld a, l
    dec b
    db $fd
    call $fffd
    ld bc, $ff01
    cp $bf
    rra
    ld [hl], c
    ld h, b
    cp a
    rst $38
    or c
    ldh [$bf], a
    rst $38
    or c
    ldh [rIE], a
    rst $38
    add b
    add b
    ld e, $1e
    pop hl
    pop hl
    cp a
    rst $38
    and c
    pop hl
    cp a
    rst $38
    and c
    pop hl
    rst $38
    rst $38
    nop
    nop
    rra
    rra
    jr nz, jr_01a_51d4

    jr nz, jr_01a_51d6

    jr nz, jr_01a_51d8

    ccf
    jr nz, jr_01a_51fa

    cpl
    ld sp, hl
    db $eb
    cp a
    xor a
    inc a
    inc a
    and $e6
    cp l
    db $fd
    and l
    push hl
    cp l
    db $fd
    and l
    push hl
    rst $38
    rst $38
    ld bc, $8001
    add b
    rst $38
    rst $38

jr_01a_51d4:
    cp a
    rst $38

jr_01a_51d6:
    pop hl
    or e

jr_01a_51d8:
    rst $38
    cp a
    rst $38
    and c
    cp a
    rst $38
    add b
    add b
    nop
    nop
    rst $38
    rst $38
    daa
    rst $38
    daa
    rst $38
    daa
    daa
    daa
    daa
    rst $38
    rst $38
    nop
    nop
    ld hl, sp-$08
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    db $fc
    inc b

jr_01a_51fa:
    db $fc
    db $f4
    rst $38
    rst $30
    rst $38
    push af
    ld bc, $ff01
    rst $38
    dec h
    rst $38
    daa
    db $fd
    rst $38
    dec h
    daa
    dec h
    db $fd
    rst $38
    ld bc, $ef01
    db $10
    rst $28
    ld de, $1eff
    ldh [$2a], a
    call nz, $cf6a
    ld e, [hl]
    reti


    ld c, a
    ldh a, [$3f]
    rst $30
    ld [$88f7], sp
    rst $38
    ld a, b
    rlca
    ld d, h
    inc hl
    ld d, [hl]
    di
    ld a, d
    sbc e
    ld a, [c]
    rrca
    db $fc
    cp d
    xor b
    cp a
    xor a
    cp a
    and b
    cp a
    xor l
    and c
    cp a
    sbc a
    sbc a
    add b
    add b
    di
    rst $38
    dec e
    rla
    db $fd
    rst $30
    db $fd
    rlca
    db $fd
    rst $30
    rst $30
    dec e
    rst $38
    ld sp, hl
    ld bc, $cf01
    rst $38
    add b
    add b
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    ld bc, $fd01
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
    rst $38
    rst $38
    add b
    add b
    call $dab2
    and l
    add sp, -$69
    jp z, $ffb5

    add b
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $b301
    ld c, l
    or a
    ld c, c
    or e
    ld c, l
    sub e
    ld l, l
    rst $38
    ld bc, $ffff
    add b
    add b
    add b
    rst $38
    cp a
    cp a
    cp a
    cp a
    and c
    and c
    cp a
    and c
    cp a
    and c
    cp a
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    adc a
    rst $38
    rlca
    adc a
    rlca
    ld [hl], a
    adc a
    adc a
    rst $38
    rst $38
    cp a
    xor a
    cp a
    xor a
    cp a
    and b
    and b
    cp a
    cp a
    and b
    and b
    cp a
    sbc a
    sbc a
    add b
    add b
    ld bc, $0101
    rst $38
    db $fd
    db $fd
    db $fd
    dec b
    db $fd
    db $fd
    dec b
    dec b
    db $fd
    dec b
    db $fd
    rst $38
    rst $38
    rst $38
    and h
    rst $38
    rst $38
    cp a
    db $e4
    and h
    rst $38
    cp a
    cp a
    rst $38
    add b
    add b
    rst $38
    rst $38
    rst $38
    rst $38
    add h
    rst $38
    rst $38
    db $fc
    db $fc
    add h
    add a
    add a
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    db $fd
    rst $30
    db $fd
    rst $30
    db $fd
    rlca
    push af
    rst $38
    db $fd
    rlca
    rlca
    db $fd
    rst $38
    ld sp, hl
    ld bc, $ff01
    rst $38
    add l
    rst $38
    rst $38
    db $fd
    add a
    cp l
    cp a
    add l
    db $fd
    rst $38
    ld bc, $ff01
    rst $38
    ld sp, hl
    rst $38
    rlca
    and a
    dec b
    rst $30
    dec b
    rla
    db $fd
    rlca
    db $fd
    rst $38
    ld bc, $ffff
    cp $ff
    ld bc, $ff01
    ld bc, $ffff
    rst $38
    rst $38
    ld bc, $ff01
    ld bc, $ffff
    rst $38
    ld a, a
    rst $38
    add b
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    add b
    rst $38
    rst $38
    rst $38
    cp $ff
    ld bc, $fd01
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    ld bc, $ffff
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    push de
    rst $38
    xor d
    rst $38
    push de
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
    ld d, l
    rst $38
    xor e
    rst $38
    ld d, l
    rst $38
    rst $38
    rst $38
    add e
    db $fc
    add a
    ld hl, sp-$71
    ldh a, [rIE]
    rst $38
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $ffff
    inc bc
    ld bc, $0103
    inc bc
    ld bc, $0103
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    jr z, jr_01a_53b3

    add hl, hl
    inc de
    jr z, jr_01a_53b7

    add hl, hl
    ld bc, $100b
    add hl, hl
    ld de, $101b
    add hl, hl
    jr z, jr_01a_53ec

    dec sp

jr_01a_53b3:
    jr z, @+$2a

    ld c, d
    ld c, e

jr_01a_53b7:
    jr z, @+$4a

    ld c, h
    ld c, l
    ld c, c
    ld c, b
    ld b, $16
    ld c, c
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld [$0808], sp
    ld a, [bc]
    jr jr_01a_53ef

    jr @+$1b

    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld [$0408], sp
    dec b
    jr jr_01a_53ff

    inc d
    dec d
    ld bc, $010b
    dec bc

jr_01a_53ec:
    ld de, $111b

jr_01a_53ef:
    dec de
    jr c, @+$0a

    ld [$1808], sp
    add hl, de
    jr jr_01a_5411

    ld bc, $010b
    dec bc
    ld de, $111b

jr_01a_53ff:
    dec de
    ld [$0808], sp
    ld [$1918], sp
    jr @+$1b

    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    inc h

jr_01a_5411:
    dec h
    add hl, sp
    dec bc
    inc [hl]
    dec [hl]
    inc a
    dec de
    ld h, $27
    ld [hl], $0b
    ld a, [hl+]
    dec hl
    ld a, [de]
    dec de
    jr z, jr_01a_544a

    jr z, @+$2a

    ld c, [hl]
    ld c, a
    ld c, [hl]
    ld c, a
    ld c, h
    ld c, l
    ld c, h
    ld c, l
    rla
    dec e
    rla
    dec e
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld bc, $0c0b
    inc c
    ld de, $1c1b
    inc e
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    inc c
    inc c

jr_01a_544a:
    ld bc, $1c0b
    inc e
    ld de, $281b
    jr z, jr_01a_547b

    jr z, jr_01a_547d

    jr z, jr_01a_547f

    jr z, jr_01a_545a

    dec bc

jr_01a_545a:
    ld bc, $110b
    dec de
    ld de, $5c1b
    ld e, l
    jr z, jr_01a_548c

    ld e, [hl]
    ld e, a
    jr z, jr_01a_5490

    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    jr nz, jr_01a_5493

    jr nz, jr_01a_5495

    jr nc, @+$33

    jr nc, jr_01a_54a9

    ld [hl+], a
    inc hl
    ld [hl+], a

jr_01a_547b:
    inc hl
    ld [hl-], a

jr_01a_547d:
    inc sp
    ld [hl-], a

jr_01a_547f:
    inc sp
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld bc, $010b
    dec bc

jr_01a_548c:
    ld de, $111b
    dec de

jr_01a_5490:
    dec sp
    jr z, jr_01a_54bb

jr_01a_5493:
    ld [bc], a
    ld c, e

jr_01a_5495:
    jr z, jr_01a_54bf

    ld [de], a
    ld c, l
    rlca
    ld [hl], $0b
    ld d, $0d
    ld a, [de]
    dec de
    ld bc, $010b
    dec bc
    ld a, [de]
    dec de
    ld de, $361b

jr_01a_54a9:
    dec bc
    ld bc, $1a0b
    dec de
    ld de, $281b
    jr z, jr_01a_54db

    jr z, jr_01a_5503

    ld c, a
    ld c, [hl]
    ld c, a
    ld c, h
    ld c, l
    ld c, h

jr_01a_54bb:
    ld c, l
    rla
    dec e
    rla

jr_01a_54bf:
    dec e
    ld e, d
    ld e, e
    ld e, d
    ld e, e
    inc l
    dec l
    inc l
    dec l
    ld l, $2f
    ld l, $2f
    ld a, $3f
    ld a, $3f
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld b, b
    ld b, c
    ld b, c

jr_01a_54db:
    ld b, e
    ld d, b
    ld d, c
    ld d, c
    ld d, e
    ld b, h
    ld b, l
    ld b, l
    ld b, a
    ld d, h
    ld d, l
    ld d, l
    ld d, a
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld [hl], $0b
    ld bc, $1a0b
    dec de
    ld de, $401b
    ld b, c
    ld b, c
    ld b, e
    ld d, b
    ld d, c
    ld d, c
    ld d, e

Call_01a_5500:
Jump_01a_5500:
    jr c, jr_01a_550a

    db $10

jr_01a_5503:
    add hl, hl
    add hl, de
    jr jr_01a_5520

    jr jr_01a_553f

    dec bc

jr_01a_550a:
    ld bc, $1a0b
    dec de
    ld de, $281b
    jr z, jr_01a_553b

    ld e, c
    jr z, @+$2a

    db $10
    add hl, hl
    ld [hl], $0b
    ld c, $0f
    ld a, [de]
    dec de
    ld e, $1f

jr_01a_5520:
    ld [hl], $0b
    ld bc, $1a0b
    dec de
    ld de, $361b
    dec bc
    ld bc, $1a0b
    dec de
    ld de, $361b
    dec bc
    ld bc, $1a0b
    dec de
    ld de, $011b
    dec bc
    inc c

jr_01a_553b:
    inc c
    ld de, $1c1b

jr_01a_553f:
    inc e
    ld bc, $090b
    ld e, b
    ld de, $111b
    dec de
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld [$0808], sp
    ld [$1918], sp
    jr @+$1b

    ld bc, $420b
    ld b, [hl]
    ld de, $521b
    ld d, [hl]
    ld b, b
    ld b, c
    ld b, c
    ld b, e
    ld d, b
    ld d, c
    ld d, c
    ld d, e
    ld b, h
    ld b, l
    ld b, l
    ld b, a
    ld d, h
    ld d, l
    ld d, l
    ld d, a
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld e, d
    ld e, e
    ld e, d
    ld e, e
    inc d
    jr z, @+$2a

    jr z, jr_01a_5582

    dec bc

jr_01a_5582:
    ld bc, $110b
    dec de
    ld de, $5a1b
    ld e, e
    ld e, d
    ld e, e
    jr z, @+$2a

    jr z, jr_01a_55b8

    db $10
    add hl, hl
    jr z, @+$3c

    db $10
    add hl, hl
    jr z, jr_01a_55e2

    db $10
    add hl, hl
    ld c, b
    ld c, h
    db $10
    add hl, hl
    ld c, b
    ld b, $04
    dec b
    jr c, jr_01a_55ac

    inc d
    dec d
    jr jr_01a_55c1

    ld bc, $010b
    dec bc

jr_01a_55ac:
    ld de, $111b
    dec de
    ld e, d
    ld e, e
    ld bc, $190b
    jr jr_01a_55c8

    dec de

jr_01a_55b8:
    ld bc, $010b
    dec bc
    ld de, $111b
    dec de
    ld e, d

jr_01a_55c1:
    ld e, e
    ld [$1908], sp
    jr @+$1a

    add hl, de

jr_01a_55c8:
    ld bc, $420b
    ld b, [hl]
    ld de, $521b
    ld d, [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld e, d
    ld e, e
    ld e, d
    ld e, e
    jr z, jr_01a_5606

    jr z, jr_01a_5608

    rst $38
    nop

jr_01a_55e2:
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01a_5606:
    nop
    nop

jr_01a_5608:
    nop
    nop
    rra
    rra
    jr nz, jr_01a_562e

    daa
    jr nz, jr_01a_5611

jr_01a_5611:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld hl, sp-$08
    inc b
    inc b
    db $e4
    inc b
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38

jr_01a_562e:
    nop
    rst $38
    jr nz, jr_01a_5652

    ld a, b
    ld e, b
    ld a, [hl]
    ld h, [hl]
    rst $28
    sub l
    ld h, e
    ld a, l
    ret nc

    xor a
    ld h, a
    ld a, a
    rst $38
    ld sp, hl
    inc b
    inc b
    ld e, $1a
    ld a, e
    ld h, a
    pop af
    xor a
    ld b, [hl]
    cp a
    sbc a
    pop af
    or $ce
    sbc b
    ld hl, sp+$7f
    ld a, a

jr_01a_5652:
    add b
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp $fe
    ld bc, $fd01
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    rst $38
    rst $38
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
    rst $38
    nop
    ldh [rIE], a
    ldh [rIE], a
    ldh [rIE], a
    ldh [rIE], a
    rst $38
    rst $38
    rst $38
    cp $ff
    ld hl, sp-$01
    db $e3
    nop
    rst $38
    rlca
    rst $38
    rra
    ld sp, hl
    ld a, a
    db $e3
    rst $38
    adc e
    rst $38
    cpl
    pop af
    cp a
    pop af
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0701
    rlca
    dec e
    dec e
    rst $38
    dec d
    rst $38
    rra
    rlca
    rlca
    dec e
    dec e
    ld [hl], l
    ld [hl], l
    rst $18
    rst $18
    ld d, c
    ld d, c
    pop af
    pop af
    ld de, $1711
    rla
    rst $38
    ld bc, $36fe
    ld a, [$f14e]
    cpl
    db $f4
    rra
    ld [c], a
    dec sp
    ldh [$7f], a
    sbc h
    sbc [hl]
    rst $38
    add b
    ld a, a
    ld l, h
    ld d, a
    ld a, d
    adc a
    db $f4
    cpl
    ld hl, sp+$47
    call c, $fe07
    cp c
    ld a, c
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
    nop
    nop
    nop
    nop
    nop

jr_01a_56f5:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    daa
    jr nz, jr_01a_572a

    jr nz, jr_01a_5725

    jr nz, jr_01a_5746

    jr nz, jr_01a_5748

    cpl
    jr c, jr_01a_573b

    ccf
    jr z, jr_01a_574e

    jr c, jr_01a_56f5

    inc b
    db $e4
    inc b
    inc b
    inc b
    db $fc
    inc b
    db $fc
    db $f4
    inc e
    db $f4
    db $fc
    inc d
    db $fc
    inc e
    nop
    rst $38
    nop
    rst $38
    nop

jr_01a_5725:
    rst $38
    nop
    rst $38
    nop
    rst $38

jr_01a_572a:
    rst $38
    nop
    nop
    rst $38
    nop
    nop
    ld a, c
    ld h, [hl]
    pop de
    cp [hl]
    ld [hl], a
    ld c, d
    push hl
    sbc e
    db $eb
    rst $18
    rst $38

jr_01a_573b:
    sbc e
    ld [hl], l
    ld d, l
    ld hl, $de21
    ld h, [hl]
    rrca
    ld sp, hl
    and d
    rst $18

jr_01a_5746:
    xor e
    push de

jr_01a_5748:
    db $db
    rst $30
    rst $38
    reti


    xor $ea

jr_01a_574e:
    ld h, [hl]
    ld h, [hl]
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    nop
    rst $38
    nop
    ld bc, $fd00
    nop
    db $fd
    nop
    db $fd
    nop
    db $fd
    nop
    db $fd
    nop
    db $fd
    rst $38
    adc e
    rst $38
    ccf
    pop af
    cp a
    db $fd
    di
    sbc l
    di
    sbc l
    di
    sbc l
    di
    sub c
    rst $38
    ld de, $d1ff
    ccf
    pop de
    ccf
    pop de
    ccf
    rst $10
    ccf
    db $dd
    ccf
    db $fd
    ld [hl], a
    ld e, l
    rst $30
    ld de, $f1f1
    pop af
    sub c
    pop af
    sub a
    rst $30
    sbc l
    db $fd
    sub l
    push af
    sbc a
    rst $38
    rst $38
    rst $38
    dec e
    dec e
    ld [hl], l
    ld [hl], l
    rst $18
    rst $18
    ld d, c
    ld e, a
    pop af
    rst $38
    ld bc, $01ff
    rst $38
    rst $38
    rst $38
    xor e
    sbc e
    call nc, $f37c
    ccf
    ret nc

    ld a, b
    ret c

    cp b
    db $ec
    cp h
    db $e3
    xor e
    db $fc
    sbc a
    db $d3
    reti


    dec hl
    ld a, $cf
    db $fc
    dec bc
    ld e, $1b
    dec e
    scf
    dec a
    rst $00
    push de
    ccf
    ld sp, hl
    ld a, a
    ld a, a
    add b
    add b
    add b
    cp a
    sbc a
    and b
    sbc a
    and b
    sbc a
    and b
    add b
    cp a
    add b
    add b
    cp $fe
    ld bc, $0101
    db $fd
    ld sp, hl
    dec b
    ld sp, hl
    dec b
    ld sp, hl
    dec b
    ld bc, $01fd
    ld bc, $c0bf
    cp a
    rst $38
    cp a
    push hl
    cp l
    push hl
    and l
    push hl
    cp a
    db $fd
    cp a
    rst $38
    cp a
    ret nz

    db $fd
    inc bc
    db $fd
    rst $38
    db $fd
    daa
    dec h
    daa
    dec h
    daa
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    inc bc
    inc a
    inc a
    ld a, [hl]
    ld a, [hl]
    rst $20
    jp $81e7


    rst $20
    add c
    rst $20
    add c
    rst $38
    sbc c
    rst $20
    and l
    ld bc, $0001
    nop
    ld [bc], a
    inc bc
    rrca
    ld c, $14
    ld e, $0e
    dec c
    inc a
    ld l, $3e
    cpl
    ld b, b
    ret nz

    ret nz

    ld b, b
    ld b, b
    ret nz

    ldh a, [rSVBK]
    xor b
    ld a, b
    ld [hl], b
    or b
    cp h
    ld [hl], h
    ld a, h
    db $f4
    nop
    rst $38
    nop
    add b
    nop
    xor d
    nop
    sub l
    nop
    xor e
    nop
    sub a
    nop
    xor a
    nop
    sbc a
    nop
    rst $38
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
    rst $38
    rst $38
    rst $38
    ld bc, $fdff
    rst $38
    dec b
    rlca
    dec b
    rlca
    dec b
    rlca
    db $fd
    rlca
    db $fd
    rst $38
    ld bc, $fdff
    inc bc
    dec b
    ei
    dec b
    ei
    dec b
    ei
    db $fd
    inc bc
    ld bc, $ffff
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    cp a
    rst $38
    and b
    ldh [$a0], a
    ldh [$a0], a
    ldh [$bf], a
    ldh [$bf], a
    rst $38
    xor b
    ld bc, $0154
    xor b
    ld bc, $0154
    xor b
    ld bc, $0154
    xor b
    ld bc, $0154
    cp $00
    db $fc
    nop
    ld hl, sp+$00
    ldh a, [rP1]
    pop hl
    nop
    jp nz, $8500

    nop
    dec bc
    nop
    rst $38
    nop
    rst $38
    inc e
    rst $28
    ld [hl], d
    cp l
    jp $afd1


    jp hl


    sub a
    pop bc
    ld a, a
    db $e3
    ld a, $fc
    ld bc, $01fc
    db $fc
    ld bc, $01fc
    db $fc
    ld bc, $01fc
    db $fc
    ld bc, $01fc
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ccf
    add b
    ld a, [hl+]
    add b
    dec d
    add b
    ld a, [hl+]
    add b
    dec d
    add b
    ld a, [hl+]
    add b
    dec d
    add b
    ld a, [hl+]
    add b
    dec d
    add b
    rst $38
    rst $38
    add b
    add b
    rst $38
    rst $38
    pop bc
    cp a
    pop bc
    cp a
    pop bc
    cp a
    pop bc
    cp a
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $ff01
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    ld h, [hl]
    ld b, d
    ld h, [hl]
    ld b, d
    ld h, [hl]
    ld b, d
    ld a, [hl]
    ld e, d
    ld a, [hl]
    ld a, [hl]
    ld h, [hl]
    ld a, [hl]
    ld h, [hl]
    ld a, [hl]
    inc a
    inc a
    cpl
    scf
    daa
    jr c, @+$13

    inc e
    rla
    rra
    inc de
    inc e
    add hl, bc
    inc c
    rlca
    rlca
    nop
    nop
    db $f4
    db $ec
    db $e4
    inc e
    ld [$e8f8], sp
    ld hl, sp+$08
    ld hl, sp+$10
    ldh a, [$e0]
    ldh [rP1], a
    nop
    adc b
    ld de, $8811
    adc b
    ld de, $8811
    adc b
    ld de, $8811
    adc b
    ld de, $8811
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    jr jr_01a_598a

    jr jr_01a_598c

    ld a, [hl]
    jr @-$17

    inc a
    rst $20
    ld h, [hl]
    rst $38
    inc a
    ld a, [hl]
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

jr_01a_598a:
    rst $38
    nop

jr_01a_598c:
    rst $38
    nop
    rst $38
    nop
    add b
    rst $38
    cp a
    ret nz

    and b
    rst $18
    and b
    rst $18
    and b
    rst $18
    cp a
    ret nz

    add b
    rst $38
    rst $38
    rst $38
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    rla
    nop
    cpl
    nop
    ld e, a
    nop

jr_01a_59b6:
    cp a
    nop
    ld a, a
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    ld h, [hl]
    jp $c366


    ld h, [hl]
    jp $c366


    ld h, [hl]
    jp $c366


    ld h, [hl]
    jp $c366


    cp $fe
    ld [bc], a
    ld [bc], a
    xor d
    xor d
    ld [bc], a
    ld [bc], a
    ld a, [$aafa]
    xor d
    ld [bc], a
    ld [bc], a
    cp $fe
    inc c
    ld c, $7f
    ld a, a
    sub c
    sub l
    sbc h
    or d
    adc [hl]
    xor c
    sbc a
    cp b
    and h
    cp a
    and a
    cp [hl]
    rra
    rra
    ld sp, $d0b1
    ret nc

    rst $18
    rst $38
    ld h, e
    ld [hl], e
    jr nc, jr_01a_59b6

    ld e, h
    sbc [hl]
    db $ec
    ld c, $00
    add b
    rst $38
    rst $38
    ld [hl], b
    ld a, b
    db $fc
    rst $38
    rst $38
    rst $38
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
    nop
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
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    nop
    rst $38
    ld hl, sp-$08

jr_01a_5a2a:
    ld a, [de]
    rra
    ld bc, $1901
    add hl, de
    nop
    nop
    cp $fe
    ld bc, $0101
    db $fd
    ld bc, $0105
    dec b
    add c
    add l
    pop bc
    push hl
    rst $38
    jr jr_01a_5a2a

    dec a
    rst $10
    ld l, l
    db $d3
    ld l, [hl]
    add e
    cp $82
    rst $38
    jp nc, $d76f

    ld l, l
    rst $38
    xor b
    rst $38
    ld d, h
    rst $38
    ld d, [hl]
    db $fd
    xor a
    ld sp, hl
    xor a
    xor c
    rst $38
    xor l
    rst $38
    rst $38
    ld d, [hl]
    and b
    nop
    ld b, b
    nop
    add b
    nop
    stop
    jr z, jr_01a_5a6a

jr_01a_5a6a:
    ld d, b
    nop
    ld [bc], a
    nop
    inc b
    nop
    jp $c381


    add c
    jp $c381


    add c
    jp $c381


    add c
    jp $c381


    add c
    ld a, [bc]
    nop
    inc d
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld d, l
    xor d
    xor d
    ld d, l
    rst $38
    rst $38
    jp $c381


    add c
    jp $c381


    add c
    add c
    rst $38
    add c
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    rst $38
    rra
    rst $38
    jr nz, @-$0e

    ld c, a
    rst $28
    sub b
    rst $28
    sub b
    rst $28
    sub b
    rst $28
    sub b
    ldh a, [$8f]
    rst $38
    ld hl, sp-$01
    inc b
    rrca
    ld a, [c]
    rst $30
    add hl, bc
    rst $30
    add hl, bc
    rst $30
    add hl, bc
    rst $30
    add hl, bc
    rrca
    pop af
    nop
    ld a, a
    nop
    ld b, b
    nop
    ld b, c
    nop
    ld b, e
    nop
    ld b, a
    nop
    ld c, a
    nop
    ld b, b
    nop
    ld a, a
    nop
    cp $00
    ld [bc], a
    nop
    ld [bc], a
    nop
    ld [bc], a
    nop
    ld a, [$fa00]
    nop
    ld [bc], a
    nop
    cp $be
    cp a
    and a
    cp [hl]
    ei
    and $e7
    cp $df
    cp $c3
    cp $c3
    cp $c7
    rst $38
    inc c
    cp $ec
    ld e, $f0
    ld b, $e0
    ld [bc], a
    ldh [rSC], a
    db $fd
    ld [bc], a
    db $fd
    ld [bc], a
    rst $38
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
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    ld a, a
    ld a, a
    ld b, b
    ld b, b
    ld d, l
    ld d, l
    ld b, b
    ld b, b
    ld e, a
    ld e, a
    ld d, l
    ld d, l
    ld b, b
    ld b, b
    ld a, a
    ld a, a
    ld bc, $0601
    ld b, $07
    rlca
    nop
    nop
    nop
    ld bc, $01ff
    rst $38
    ld bc, $ffff
    sub c
    cp l
    adc l
    xor l
    rrca
    cpl
    rrca
    cpl
    ccf
    rst $38
    db $fd
    db $fd
    ei
    db $fd
    db $eb
    push af
    cp a
    cp a
    sbc a
    xor a
    sbc a
    and c
    sbc a
    and c
    add e
    and b
    add b
    and b
    add b
    cp a
    add b
    add b
    rst $38
    ldh a, [$f0]
    or $30
    jr nc, jr_01a_5b87

    or $30
    or b
    or b
    or c
    cp a
    cp a
    ld a, [hl]
    ld a, a
    rst $38
    rlca
    rlca
    rlca
    rlca
    rlca
    rrca
    rra
    ld a, [hl-]
    ld a, h
    add sp, -$10
    add b
    rst $38
    add b
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $28
    ldh a, [rLCDC]
    add b
    nop
    nop
    nop
    nop
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    cp $ff
    rst $38
    nop
    nop

jr_01a_5b87:
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    nop
    nop
    cp c
    push bc
    pop af
    dec b
    pop bc
    dec b
    ld bc, $0105
    dec b
    ld bc, $0105
    db $fd
    ld bc, $ff01
    ret nz

    cp a
    and b
    sbc a
    adc a
    sbc b
    adc b
    sbc b
    adc b
    rst $18
    ld c, a
    rst $38
    jr nz, @+$01

    rra
    rst $38
    inc bc
    db $fd
    rlca
    ld sp, hl
    rst $30
    add hl, de
    rla
    add hl, de
    rla
    ei
    or $ff
    inc b
    rst $38
    ld hl, sp+$55
    xor d
    nop
    nop
    nop
    nop
    xor d
    ld d, l
    ld d, l
    xor d
    nop
    nop
    nop
    nop
    xor d
    ld d, l
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0111
    jr nz, jr_01a_5c05

    ld bc, $3211
    inc sp
    ld de, $2001
    ld hl, $1101
    ld [hl-], a
    inc sp
    jr nz, jr_01a_5c13

    ld de, $3201
    inc sp
    ld bc, $2011
    ld hl, $0111
    ld [hl-], a
    inc sp
    ld bc, $0011
    nop
    nop
    nop
    nop

jr_01a_5c05:
    nop
    nop
    nop
    ld de, $1101
    ld bc, $1101
    ld bc, $3711
    jr c, @+$3a

jr_01a_5c13:
    scf
    scf
    jr c, jr_01a_5c4f

    scf
    scf
    jr c, @+$3a

    scf
    scf
    jr c, jr_01a_5c57

    scf
    ld a, [bc]
    dec bc
    ld de, $1a01
    dec de
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0605
    nop
    nop
    dec d
    ld d, $00
    nop
    dec h
    ld h, $11
    ld bc, $3635
    ld bc, $0011
    nop
    dec b
    ld b, $00
    nop
    dec d
    ld d, $11
    ld bc, $2625
    ld bc, $3511

jr_01a_5c4f:
    ld [hl], $11
    ld bc, $1817
    ld bc, $1711

jr_01a_5c57:
    jr @+$13

    ld bc, $1817
    ld bc, $1711
    jr jr_01a_5c78

    jr jr_01a_5c74

    ld bc, $1817
    ld bc, $1711
    jr jr_01a_5c7c

    ld bc, $1817
    ld bc, $1011
    db $10
    db $10
    db $10

jr_01a_5c74:
    db $10
    db $10
    db $10
    db $10

jr_01a_5c78:
    db $10
    db $10
    db $10
    db $10

jr_01a_5c7c:
    db $10
    db $10
    db $10
    db $10
    ld de, $1101
    ld bc, $1101
    ld bc, $0411
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    ld de, $0701
    add hl, bc
    ld bc, $3211
    inc sp
    inc b
    inc b
    ld de, $1401
    inc d
    ld bc, $0911
    ld [$0605], sp
    ld [hl-], a
    inc sp
    dec d
    ld d, $11
    ld bc, $2625
    ld bc, $3511
    ld [hl], $05
    ld b, $07
    add hl, bc
    dec d
    ld d, $32
    inc sp
    dec h
    ld h, $11
    ld bc, $3635
    ld bc, $0911
    ld [$0111], sp
    ld [hl-], a
    inc sp
    ld bc, $1111
    ld bc, $0404
    ld bc, $1411
    inc d
    add hl, bc
    ld [$0111], sp
    rla
    jr @+$03

    ld de, $1817
    ld de, $1701
    jr @+$03

    ld de, $0111
    rlca
    add hl, bc
    ld bc, $1711
    jr jr_01a_5cfa

    ld bc, $1817
    ld bc, $1711
    jr jr_01a_5d02

    ld bc, $0111
    ld bc, $0111
    ld de, $0807

jr_01a_5cfa:
    ld de, $1701
    jr @+$03

    ld de, $0111

jr_01a_5d02:
    ld de, $0101
    ld de, $1101
    ld de, $0701
    ld [$1101], sp
    rla
    jr @+$13

    ld bc, $0907
    ld bc, $3211
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $0911
    ld [$0111], sp
    ld [hl-], a
    inc sp
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $2120
    rlca
    ld [$3332], sp
    ld [hl+], a
    inc hl
    jr nz, @+$23

    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl+], a
    inc hl
    rlca
    ld [$2120], sp
    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl+], a
    inc hl
    jr nz, jr_01a_5d6d

    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    jr nz, jr_01a_5d73

    ld de, $3201
    inc sp
    ld bc, $2011
    ld hl, $2120
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $2001
    ld hl, $1101
    ld [hl-], a
    inc sp
    jr nz, jr_01a_5d8b

    jr nz, @+$23

    ld [hl-], a

jr_01a_5d6d:
    inc sp
    ld [hl-], a
    inc sp
    rla
    jr @+$13

jr_01a_5d73:
    ld bc, $3332
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0111
    rla
    jr @+$03

    ld de, $3332
    ld de, $1101

jr_01a_5d8b:
    ld bc, $1101
    ld bc, $2011
    ld hl, $2120
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    jr nz, @+$23

    ld de, $3201
    inc sp
    ld bc, $2011
    ld hl, $2120
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $2001
    ld hl, $1101
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $2011
    ld hl, $2120
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    jr nz, jr_01a_5de3

    jr nz, jr_01a_5de5

    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0907
    ld bc, $3211
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $0911
    add hl, bc
    add hl, bc

jr_01a_5de3:
    add hl, bc
    ld [hl-], a

jr_01a_5de5:
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $0911
    ld [$0111], sp
    ld [hl-], a
    inc sp
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0d0c
    jr nz, @+$23

    inc e
    dec e
    ld [hl-], a
    inc sp
    jr nz, jr_01a_5e2b

    jr nz, jr_01a_5e2d

    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0907
    ld bc, $3211
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $0911
    add hl, bc
    add hl, bc

jr_01a_5e2b:
    add hl, bc
    ld [hl-], a

jr_01a_5e2d:
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $0911
    ld [$0111], sp
    ld [hl-], a
    inc sp
    ld bc, $2011
    ld hl, $0111
    ld [hl-], a
    inc sp
    ld bc, $1711
    jr jr_01a_5e5c

    ld bc, $1817
    ld bc, $2b11
    add hl, hl
    dec hl
    add hl, hl
    dec sp
    ld a, [hl+]
    dec sp
    ld a, [hl+]
    scf
    jr c, jr_01a_5e93

    scf

jr_01a_5e5c:
    scf
    jr c, @+$3a

    scf
    ld de, $1101
    ld bc, $1101
    ld bc, $2011
    ld hl, $0907
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    rla
    jr jr_01a_5e84

    ld bc, $1817
    ld bc, $2011
    ld hl, $0111
    ld [hl-], a
    inc sp
    ld bc, $1111
    ld bc, $2120

jr_01a_5e84:
    ld bc, $3211
    inc sp
    ld de, $1701
    jr @+$03

    ld de, $1817
    ld de, $1101

jr_01a_5e93:
    ld bc, $1101
    ld c, $0f
    ld de, $1e01
    rra
    ld bc, $3211
    inc sp
    ld de, $1101
    ld bc, $0f0e
    ld bc, $1e11
    rra
    ld de, $3201
    inc sp
    ld bc, $0011
    nop
    nop
    nop
    nop
    nop
    ld c, $0f
    ld de, $1e01
    rra
    ld bc, $3211
    inc sp
    nop
    nop
    nop
    nop
    ld c, $0f
    nop
    nop
    ld e, $1f
    ld de, $3201
    inc sp
    ld bc, $1711
    jr jr_01a_5ee4

    ld bc, $1817
    ld bc, $2011
    ld hl, $2120
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    add hl, bc
    ld [$2120], sp

jr_01a_5ee4:
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $2011
    ld hl, $0907
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $3a11
    ld a, [hl-]
    dec l
    dec a
    ld a, [hl-]
    dec l
    dec a
    ld a, [hl-]
    dec l
    dec a
    ld a, [hl-]
    ld a, [hl-]
    dec a
    ld a, [hl-]
    ld a, [hl-]
    dec l
    ld a, [hl-]
    ld a, [hl-]
    dec l
    ld a, $3a
    dec l
    dec a
    ld a, $2d
    dec a
    ld a, [hl-]
    ld a, $3d
    ld a, [hl-]
    ld a, [hl-]
    ld a, $3e
    ld a, [hl-]
    dec l
    dec a
    ld a, $2d
    dec a
    ld a, [hl-]
    ld a, $3d
    ld a, [hl-]
    ld a, [hl-]
    ld a, $3a
    ld a, [hl-]
    dec l
    ld de, $2401
    inc h
    ld bc, $3411
    inc [hl]
    ld de, $3901
    add hl, sp
    ld bc, $0111
    ld de, $2424
    ld de, $3401
    inc [hl]
    ld bc, $3911
    add hl, sp
    ld de, $0101
    ld de, $1101
    ld de, $0201
    inc bc
    ld bc, $1211
    inc de
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0111
    ld a, [bc]
    dec bc
    ld bc, $1a11
    dec de
    dec b
    ld b, $11
    ld bc, $1615
    ld bc, $2511
    ld h, $11
    ld bc, $3635
    ld bc, $0211
    inc bc
    ld de, $1201
    inc de
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $4848
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld de, $1101
    ld bc, $1101
    ld bc, $4811
    ld c, b
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld b, b
    ld b, c
    ld b, d
    ld b, e
    ld d, b
    ld d, c
    ld d, d
    ld d, d
    ld c, b
    ld c, b
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld b, h
    ld b, l
    ld de, $5401
    ld d, l
    ld bc, $5611
    ld d, a
    ld e, b
    ld e, c
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $2827
    ld bc, $3011
    ld b, [hl]
    ld de, $3101
    inc a
    ld bc, $3211
    inc sp
    jr z, jr_01a_600a

    jr z, @+$2a

    ld b, a
    ld a, [hl-]
    ld a, [hl-]
    ld b, [hl]
    ld d, e
    ccf
    inc a
    inc a
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld [bc], a
    inc bc
    ld de, $1201
    inc de
    ld bc, $0211
    inc bc
    ld de, $1201
    inc de
    ld bc, $4811
    ld c, b
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    rlca
    ld [$0111], sp

jr_01a_600a:
    rla
    jr @+$03

    ld de, $1817
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $2827
    ld bc, $3011
    ld b, [hl]
    ld de, $1101
    ld bc, $1101
    ld bc, $2811
    jr z, @+$2a

    jr z, jr_01a_6074

    ld a, [hl-]
    ld a, [hl-]
    ld b, [hl]
    rla
    jr jr_01a_6044

    ld bc, $1817
    ld bc, $1711
    jr @+$13

    ld bc, $1817
    ld bc, $1111
    ld bc, $0111

jr_01a_6044:
    ld bc, $0111
    ld de, $0807
    ld de, $1701
    jr @+$03

    ld de, $0111
    ld sp, $013c
    ld de, $3332
    ld de, $1101
    ld bc, $1101
    ld bc, $5311
    ccf
    inc a
    inc a
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $1817

jr_01a_6074:
    ld bc, $1711
    jr @+$13

    ld bc, $1817
    ld bc, $3211
    inc sp
    ld e, d
    ld e, e
    ld de, $3201
    inc sp
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0111
    rla
    jr @+$03

    ld de, $1817
    ld de, $1701
    jr @+$03

    ld de, $1817
    rlca
    ld [$0807], sp
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [bc], a
    inc bc
    ld de, $1201
    inc de
    ld bc, $0211
    inc bc
    ld de, $1201
    inc de
    ld bc, $4c11
    ld c, l
    ld de, $5c01
    ld e, l
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $4848
    ld c, [hl]
    ld c, a
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0909
    add hl, bc
    add hl, bc
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0d0c
    ld bc, $1c11
    dec e
    jr z, jr_01a_611b

    ld de, $4701
    inc l
    ld bc, $3c11
    inc l
    ld de, $3201
    inc sp
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0909
    add hl, bc

jr_01a_611b:
    ld [$3332], sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $0711
    add hl, bc
    add hl, bc
    add hl, bc
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0b0a
    ld bc, $1a11
    dec de
    ld de, $1101
    ld bc, $1101
    ld bc, $2811
    add hl, de
    ld de, $4701
    inc l
    ld bc, $1111
    ld bc, $2827
    ld bc, $3011
    ld l, $11
    ld bc, $3c31
    ld bc, $3211
    inc sp
    jr z, @+$2a

    jr z, jr_01a_618c

    ld l, $3a
    ld a, [hl-]
    ld l, $53
    ccf
    inc a
    inc a
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    jr z, @+$1b

    ld de, $2e01
    inc l
    ld bc, $3c11
    inc l
    ld de, $3201
    inc sp
    ld bc, $3c11
    inc l
    ld de, $3201
    inc sp
    ld bc, $1111
    ld bc, $0111

jr_01a_618c:
    ld bc, $0111
    ld de, $4848
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld de, $1101
    ld bc, $1101
    ld bc, $2b11
    add hl, hl
    dec hl
    add hl, hl
    dec sp
    ld a, [hl+]
    dec sp
    ld a, [hl+]
    ld de, $1101
    ld bc, $1101
    ld bc, $4811
    ld c, b
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld de, $1101
    ld bc, $1101
    ld bc, $4811
    ld c, b
    ld c, b
    ld c, b
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0807
    ld de, $1701
    jr @+$03

    ld de, $1817
    ld de, $3201
    inc sp
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $0807
    ld de, $1701
    jr @+$03

    ld de, $1817
    ld de, $3201
    inc sp
    ld bc, $0711
    ld [$0605], sp
    rla
    jr jr_01a_621c

    ld d, $17
    jr @+$27

    ld h, $32
    inc sp
    dec [hl]
    ld [hl], $11
    ld bc, $0605
    ld bc, $1511
    ld d, $07
    ld [$2625], sp

jr_01a_621c:
    rla
    jr jr_01a_6254

    ld [hl], $17
    jr @+$07

    ld b, $32
    inc sp
    dec d
    ld d, $11
    ld bc, $2625
    ld bc, $3511
    ld [hl], $5e
    ld e, [hl]
    ld de, $3801
    jr c, @+$03

    ld de, $3838
    ld de, $5e01
    ld e, [hl]
    ld bc, $1111
    ld bc, $5e5e
    ld bc, $3811
    jr c, jr_01a_625a

    ld bc, $3838
    ld bc, $5e11
    ld e, [hl]
    db $10
    db $10
    db $10
    db $10

jr_01a_6254:
    db $10
    db $10
    db $10
    db $10
    jr nz, @+$23

jr_01a_625a:
    jr nz, @+$23

    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1701
    jr @+$03

    ld de, $3332
    jr c, jr_01a_62a1

    ld de, $3801
    scf
    ld bc, $3811
    scf
    ld de, $3801
    scf
    ld bc, $1111
    ld bc, $0807
    ld bc, $1711
    jr jr_01a_6292

    ld bc, $3837
    ld bc, $3711
    jr c, @+$09

    ld [$0111], sp
    rla
    jr @+$03

    ld de, $1817

jr_01a_6292:
    ld de, $3201
    inc sp
    ld bc, $1111
    ld bc, $3837
    ld bc, $3711
    jr c, @+$13

jr_01a_62a1:
    ld bc, $3838
    ld bc, $5e11
    ld e, [hl]
    add hl, bc
    ld [$0111], sp
    ld [hl-], a
    inc sp
    ld bc, $3811
    jr c, jr_01a_62c4

    ld bc, $5e5e
    ld bc, $1111
    ld bc, $0907
    ld bc, $3211
    inc sp
    add hl, bc
    ld [$0111], sp

jr_01a_62c4:
    ld [hl-], a
    inc sp
    ld bc, $1111
    ld bc, $5e5e
    ld bc, $3811
    jr c, jr_01a_62e2

    ld bc, $0907
    ld bc, $3211
    inc sp
    ld e, [hl]
    ld e, [hl]
    ld de, $3801
    jr c, @+$03

    ld de, $3837

jr_01a_62e2:
    jr c, @+$39

    scf
    jr c, jr_01a_631f

    scf
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0111
    ld bc, $0111
    ld de, $3837
    jr c, jr_01a_6333

    scf
    jr c, jr_01a_6337

    scf
    ld c, b
    ld c, b
    dec hl
    add hl, hl
    ld c, d
    ld c, d
    dec sp
    ld a, [hl+]
    ld de, $1101
    ld bc, $1101
    ld bc, $1111
    ld bc, $0605
    ld bc, $1511
    ld d, $11
    ld bc, $2625
    ld bc, $3511

jr_01a_631f:
    ld [hl], $64
    ld h, l
    ld h, [hl]
    ld h, a
    ld [hl], h
    ld [hl], l
    db $76
    ld [hl], a
    add h
    add l
    add [hl]
    add a
    sub h
    sub l
    sub [hl]
    sub a
    ld l, b
    ld l, c
    ld l, d

jr_01a_6333:
    ld l, e
    ld a, b
    ld a, c
    ld a, d

jr_01a_6337:
    ld a, e
    adc b
    adc c
    adc d
    adc e
    sbc b
    sbc c
    sbc d
    sbc e
    ld l, b
    ld l, c
    ld l, d
    ld l, e
    ld a, b
    ld a, c
    ld a, d
    ld a, e
    adc b
    adc c
    adc d
    adc e
    sbc b
    sbc c
    sbc d
    sbc e
    ld h, b
    ld h, c
    ld h, d
    ld h, e
    ld [hl], b
    ld [hl], c
    ld [hl], d
    ld [hl], e
    add b
    add c
    add d
    add e
    sub b
    sub c
    sub d
    sub e
    ld h, h
    ld h, l
    ld h, [hl]
    ld h, a
    ld [hl], h
    ld [hl], l
    db $76
    ld [hl], a
    add h
    add l
    add [hl]
    add a
    sub h
    sub l
    sub [hl]
    sub a
    ld l, b
    ld l, c
    ld l, d
    ld l, e
    ld a, b
    ld a, c
    ld a, d
    ld a, e
    adc b
    adc c
    adc d
    adc e
    sbc b
    sbc c
    sbc d
    sbc e
    ld l, h
    ld l, l
    ld l, [hl]
    ld l, a
    ld a, h
    ld a, l
    ld a, [hl]
    ld a, a
    adc h
    adc l
    adc [hl]
    adc a
    sbc h
    sbc l
    sbc [hl]
    sbc a
    and b
    and c
    and d
    and e
    or b
    or c
    or d
    or e
    ret nz

    pop bc
    jp nz, $d0c3

    pop de
    jp nc, $a4d3

    and l
    and [hl]
    and a
    or h
    or l
    or [hl]
    or a
    call nz, $c6c5
    rst $00
    call nc, $d6d5
    rst $10
    xor b
    xor c
    xor d
    xor e
    cp b
    cp c
    cp d
    cp e
    ret z

    ret


    jp z, $d8cb

    reti


    jp c, $acdb

    xor l
    xor [hl]
    xor a
    cp h
    cp l
    cp [hl]
    cp a
    call z, $cecd
    rst $08
    call c, $dedd
    rst $18
    nop
    nop
    ld b, c
    nop
    ld [$0000], sp
    nop
    add b
    nop
    ld bc, $0000
    nop
    ld b, b
    nop
    rst $38
    rst $38
    add c
    rst $38
    add c
    rst $38
    rst $38
    add c
    rst $38
    rst $38
    add c
    add c

jr_01a_63ec:
    add c
    add c
    rst $38
    rst $38
    ld a, [hl+]
    nop
    ld d, l
    nop
    xor b
    nop
    ld b, e
    rlca
    adc e
    ld [$1044], sp
    sub h
    db $10
    ld d, e
    db $10
    xor d
    nop
    ld d, l
    nop
    ld a, [bc]
    nop
    pop de
    ldh [$da], a
    db $10
    ld hl, $2a08
    ld [$08c9], sp
    nop
    nop
    nop
    inc d
    nop
    ld b, c
    dec b
    dec b
    dec bc
    dec bc
    inc b
    ld b, $08
    dec c
    jr jr_01a_643a

    ld [bc], a
    ld [bc], a
    dec l
    dec a
    ld d, l
    ld d, l
    jp nc, Jump_000_00d2

    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    ld b, b
    ld b, b
    or b
    or h
    xor a
    xor a
    ld c, d
    jp z, Jump_01a_5500

jr_01a_643a:
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    nop
    nop
    inc d
    nop
    ld b, c
    and b
    and b
    ret nc

    ret nc

    jr nz, jr_01a_63ec

    db $10
    ldh a, [$58]
    ld hl, sp+$1f
    rra
    jr nz, @+$22

    jr nz, jr_01a_6476

    ccf
    ccf
    db $10
    ccf
    jr nz, jr_01a_647c

    ccf
    jr nz, jr_01a_649e

    jr nz, @+$01

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
    nop
    rst $38
    nop
    rst $38
    nop
    ld bc, $3601
    ld [hl], $7a
    ld c, [hl]

jr_01a_6476:
    ld sp, $142f
    rra
    ld [hl+], a
    dec sp

jr_01a_647c:
    ld h, b
    ld a, a
    sbc h
    sbc [hl]
    add b
    add b

jr_01a_6482:
    ld l, h
    ld l, h
    ld d, [hl]
    ld a, d
    adc h
    db $f4
    jr z, jr_01a_6482

    ld b, h
    call c, $fe06
    cp c
    ld a, c
    ld hl, sp-$08
    inc b
    inc b
    inc b
    inc b
    db $fc
    db $fc
    inc b
    db $fc
    inc b
    inc b
    db $fc
    inc b

jr_01a_649e:
    db $fc
    inc b
    rra
    rra
    ld d, b
    inc d
    rla
    rla
    rla
    rla
    sub b
    inc d
    rla
    rla
    rla
    rla
    ld d, b
    inc d
    ret z

    push af
    add e
    ld a, [$76ae]
    rst $18
    xor h
    or $54
    db $ec
    pop hl
    db $db
    jp nz, $81ed

    inc sp
    xor a
    ld b, c
    rst $18
    ld [hl], e
    xor $7e
    push af
    dec a
    ld [$f75c], a
    ld a, a
    db $eb
    db $fd
    rst $10
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    ld h, [hl]
    ld h, [hl]
    xor d
    xor d
    ld [$8aea], a
    adc d
    adc h
    adc h
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    and [hl]
    and [hl]
    xor b
    xor b
    adc $ce
    xor b
    xor b
    xor [hl]
    xor [hl]
    sub b
    jr @+$57

    ld a, [de]
    ld [hl], $38
    ld d, [hl]
    ld a, b
    and $78
    rst $38
    adc h
    ld [hl], d
    rst $38
    inc b
    ld [hl], c
    ld a, [bc]
    jr jr_01a_656c

    sbc b
    ld l, $5c
    ld a, [hl+]
    ld e, d
    ld h, h
    ld e, $e3
    ld a, $fe
    ld a, [hl-]
    push bc
    db $fc
    nop
    inc a
    nop
    adc c
    nop
    ld h, b
    nop
    rst $30
    nop
    rst $20
    nop
    rst $20
    nop
    sbc e
    nop
    call c, Call_01a_5500
    and b
    xor d
    ld d, b
    ld a, a
    and b
    cp d
    nop
    ld d, l
    nop
    xor d
    nop
    push af
    nop
    rst $38
    ld [bc], a
    ld d, a
    dec b
    xor a
    ld [bc], a
    ld d, a
    nop
    xor e
    nop
    ld d, a
    nop
    cp a
    nop
    rst $38
    nop
    rst $38
    and h
    db $fc
    ld e, b
    db $fc
    adc h
    db $fd
    ld [de], a
    cp $0e
    cp $29
    rst $38
    ld d, [hl]
    cp $2a
    rst $38
    ccf
    jr nz, jr_01a_6563

    ccf
    jr nz, jr_01a_6576

    ccf
    jr nz, jr_01a_6598

    jr nz, jr_01a_659a

    jr nz, jr_01a_659c

    ccf
    jr nz, jr_01a_659f

    rst $38
    nop
    nop

jr_01a_6563:
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop

jr_01a_656c:
    rst $38
    rst $38
    nop
    rst $38
    xor e
    sbc e
    ld d, h
    ld a, h
    inc sp
    ccf

jr_01a_6576:
    ld d, b
    ld a, b
    ret c

    cp b
    db $ec
    cp h
    db $e3
    xor e
    db $fc
    sbc a
    db $d3
    reti


    ld a, [hl+]
    ld a, $cc
    db $fc
    ld a, [bc]
    ld e, $1b
    dec e
    scf
    dec a

jr_01a_658c:
    rst $00
    push de
    ccf
    ld sp, hl
    db $fc
    inc b
    ld [$04f8], sp
    inc b
    db $fc
    inc b

jr_01a_6598:
    db $fc
    inc b

jr_01a_659a:
    db $fc
    inc b

jr_01a_659c:
    db $fc
    db $fc
    inc b

jr_01a_659f:
    db $fc
    ld bc, $0301
    inc bc
    ld c, $0e
    rra
    inc e
    ld [hl], $34
    ld l, h
    ld h, c
    ld e, e
    ld b, d
    db $ed
    add c
    rst $38
    rst $38
    inc a
    inc a
    xor d
    nop
    rst $10
    nop
    ld a, d
    nop
    pop af
    nop
    ld a, [$bf00]
    nop
    add b
    add b
    ret nz

    ret nz

    ld [hl], b
    ldh a, [$58]
    ld hl, sp+$3c
    db $ec
    ld e, h
    db $f4
    ld a, [hl]
    ld [$d7fd], a
    ld bc, $2000
    ld b, h
    nop
    xor d
    add hl, hl
    sub d
    inc [hl]
    ld c, d
    or l
    ld c, d
    db $d3
    inc l
    ld h, [hl]
    jr jr_01a_658c

    ld bc, $1643
    rst $38
    ld a, a
    add b
    rst $38
    add b
    add b
    rst $38
    and [hl]
    or a
    or [hl]
    db $fc
    add b
    xor d
    add b
    pop bc
    ld d, h
    cp $ff
    ld bc, $01ff
    ld bc, $99ff
    ld a, [c]
    jp nc, Jump_000_0101

    or l
    dec a
    ld e, d
    ld a, [de]
    or l
    ld [hl], l

jr_01a_6606:
    ld b, d
    ld a, d
    add sp, $7d
    sub b
    rst $38
    ldh [$7f], a
    ld c, d
    rst $38
    or h
    rst $38
    ld l, d
    ld a, a
    sub l
    rst $38
    ld h, b
    ld a, d
    ld c, b
    ld a, l
    jr nc, jr_01a_665b

    dec e
    rra
    rlca
    rlca
    ld b, b
    rst $38
    xor d
    cp a
    inc b
    ld e, a
    ld [$05bf], sp
    ld a, a
    ld a, [hl+]
    rst $38
    ld d, h
    rst $38
    xor d
    rst $38
    ld bc, $00ff
    rst $38
    dec d
    rst $38
    xor d
    rst $38
    inc b
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    adc [hl]
    cp $09
    ld e, a
    ld b, $ae
    ld [de], a
    cp $2c
    db $fc
    jr c, jr_01a_6606

    ldh [$e0], a
    rra
    rra
    ld a, c
    rrca
    ld a, c
    rrca
    ld a, l
    dec bc
    ld a, l
    dec bc
    ld a, l

jr_01a_665b:
    dec bc
    ld a, l
    dec bc
    ld a, l
    dec bc
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    ccf
    rst $38
    ld h, h
    cp a
    ld h, h
    cp a
    ld h, h
    cp a
    ld h, h
    cp a
    ld h, [hl]
    cp l

Jump_01a_667e:
    ld [hl], l
    xor [hl]
    rst $38
    rst $38
    db $fc
    rst $38
    ld h, $fd
    ld h, $fd
    ld h, $fd
    ld h, $fd
    and [hl]
    ld a, l
    ld h, [hl]
    cp l
    ld a, [$9ef8]
    ldh a, [$9e]
    ldh a, [$be]
    ret nc

    cp [hl]
    ret nc

    cp [hl]
    ret nc

    cp [hl]
    ret nc

    cp [hl]
    ret nc

    push af
    pop bc
    ei
    ret nz

    db $76
    ld h, d
    xor a
    xor h
    ld d, [hl]
    ld b, h
    db $ed
    add b
    jp nc, $e982

    add c
    db $eb

jr_01a_66b1:
    nop
    sub $00
    adc e
    nop
    rst $18
    nop
    ld a, d
    nop
    pop af
    nop
    ld a, [$bf00]
    nop
    cp e
    xor a
    ld d, a
    rst $18
    ld a, a
    xor $7f
    push af
    ccf
    ld [$f75d], a
    ld a, a
    db $eb
    db $fd
    rst $10
    nop
    nop
    ld b, c
    nop
    ld [$0000], sp
    nop
    add b
    nop
    ld bc, $0000
    nop
    ld b, b
    nop
    ret nz

    ld b, b
    rst $38
    sub l
    add b
    add b
    ld a, a
    ld a, a
    xor d
    rlca
    ld d, e
    ld c, $a1
    rrca
    ld d, b
    rlca
    ld bc, $ff01
    ld d, c
    ld bc, $ff01
    cp $4a

Call_01a_66f9:
    ldh [$c5], a
    ld [hl], b
    adc d
    ldh a, [$15]
    ldh [rIE], a
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
    and d
    ld [$1441], sp
    sub b
    ld h, a
    jr nz, jr_01a_66b1

    ld l, h
    sub d
    db $10
    ld l, l
    sub h
    ld c, c
    ld b, c
    ld [hl], $ed
    rst $38
    ld e, $1f
    dec [hl]
    ld a, a
    ld d, b
    ld hl, sp+$60
    ld hl, sp-$74
    adc h
    ld [hl], d
    rst $38
    nop
    ld a, a
    ld d, a
    rst $38
    cp b
    db $fc
    inc c
    ld a, [hl]
    ld a, [bc]
    dec de
    inc b
    rra
    ld [hl+], a
    ccf
    ld a, [hl-]
    dec sp
    db $e4
    cp $00
    nop
    ld [bc], a
    jr jr_01a_6755

    inc h
    inc c
    ld [hl-], a
    ld b, b
    ld e, $0a
    inc b
    jr nz, jr_01a_678e

    ld b, h
    jr nz, jr_01a_67ce

    dec bc
    ld a, l
    dec bc
    ld a, l

jr_01a_6755:
    dec bc
    ld a, l
    dec bc
    ld a, l
    dec bc
    ld a, c
    rrca
    ld a, c
    rrca
    ld a, a
    ld b, $40
    nop
    nop
    add hl, bc
    db $10
    ld b, l
    ld [bc], a
    dec l
    db $10
    rrca
    ld a, [hl+]
    dec d
    ld c, c
    nop
    nop
    nop
    ld l, $b5
    dec [hl]
    xor [hl]
    inc l
    or a
    inc [hl]
    xor a
    inc h
    cp a
    ld h, h
    cp a
    ld a, a
    cp a
    rst $38
    ret nz

    and h
    ld a, l
    ld h, h
    cp l
    inc h
    db $fd
    inc h
    db $fd
    inc h
    db $fd
    ld h, $fd
    cp $fd

jr_01a_678e:
    rst $38
    inc bc
    cp [hl]
    ret nc

    cp [hl]
    ret nc

    cp [hl]
    ret nc

    cp [hl]
    ret nc

    cp [hl]
    ret nc

    sbc [hl]
    ldh a, [$9e]
    ldh a, [$fe]
    ld h, b
    push de
    add c
    ld hl, sp-$1e
    pop af
    call nc, $8dda
    db $e4
    sbc d
    ld a, [$78b5]
    rst $28
    ccf
    rst $10
    push de
    and e
    ld b, h
    ld e, [hl]
    sbc b
    dec a
    ld e, l
    cp d
    inc a
    ld d, a
    ld a, h
    xor a
    dec sp
    rst $30
    rst $38
    pop hl
    rst $38
    xor e
    ld d, l
    ld e, a
    cp e
    cpl
    ld e, l
    or a
    dec hl
    ld e, a
    ld e, l
    xor a
    ld e, $f7

jr_01a_67ce:
    db $fc
    db $eb
    adc a
    ldh a, [$8f]
    ldh a, [$80]
    rst $38
    rst $38
    rst $38
    adc a
    ldh a, [$8f]
    ldh a, [$80]
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $01ff
    ld bc, $ffff
    rst $38
    rst $38
    ld bc, $01ff
    ld bc, $ffff
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    inc h
    rst $38
    inc a
    rst $20
    inc a
    rst $20
    inc a
    rst $20
    inc a
    rst $20
    inc a
    rst $20
    inc a
    rst $20
    rst $38
    rst $20
    inc a
    rst $20
    inc a
    rst $20
    jr @+$01

    jr @+$3e

    dec h
    and l
    ld a, a
    ld b, e
    ld a, [hl]
    jp c, $e666

    ld hl, $41e1
    ret nz

    ld b, c
    ret nz

    ld h, b
    ld a, h
    sbc b
    sbc c
    and h
    xor h
    ld d, h
    ld c, a
    inc d
    rrca
    xor b
    adc a
    ld a, b
    ld a, e
    ld b, h
    ld b, h
    add d
    ldh a, [$80]
    db $fc
    adc e
    rst $38
    ld h, l
    rst $38
    dec sp
    rst $38
    dec bc
    xor $00
    sbc e
    nop
    call c, $86a6
    sbc l
    add e
    rlca
    ld bc, $0d83
    ld d, l
    cp a
    xor d
    ld a, a
    call nc, $10ff
    db $fc
    res 7, a
    ld h, a
    sbc $3f
    db $ed
    ld e, $fb
    dec e
    ei
    ld a, $e7
    ld l, d
    rst $18
    push bc
    cp a
    add c
    rst $38
    jp Jump_01a_667e


    cp l
    inc a
    db $db
    cp [hl]
    ei
    ld a, l
    rst $20
    or $df
    jp hl


    cp a
    push de
    ld sp, hl
    ld l, e
    ld [hl], d
    or [hl]
    or l
    ld e, l
    jp c, $dd9a

    ld h, l
    and $d2
    ld a, e
    xor c
    push af
    rst $38
    rst $38
    cp a
    add b
    cp a
    sbc a
    or b
    sub b
    or b
    sub b
    cp a
    sbc a
    ld a, a
    ret nz

    ccf
    rst $38
    rst $38
    rst $38
    ld sp, hl
    rlca
    ld sp, hl
    rst $38
    add hl, bc
    rrca
    add hl, bc
    rrca
    ld sp, hl
    rst $38
    ld a, [$fc07]
    rst $38
    add b
    cp h
    ld h, b
    jp hl


    db $10
    ldh a, [$08]
    rst $38
    inc d
    rst $38
    ld a, $e7
    ld l, d

jr_01a_68ad:
    rst $18
    push bc
    cp a
    ld bc, $073d
    adc [hl]

jr_01a_68b4:
    ld c, $6d
    dec d
    ld a, [$fd2a]
    ld b, l
    and $52
    ei
    xor c
    push af
    ld hl, sp-$08
    add hl, bc
    jr z, jr_01a_68ad

    add sp, -$18
    add sp, $08
    jr z, jr_01a_68b4

    add sp, -$18
    add sp, $08
    jr z, jr_01a_68d1

jr_01a_68d1:
    stop
    jr c, jr_01a_68d5

jr_01a_68d5:
    ld a, h
    nop
    cp $00
    nop
    nop
    jr c, jr_01a_68dd

jr_01a_68dd:
    jr c, jr_01a_68df

jr_01a_68df:
    jr c, jr_01a_68e1

jr_01a_68e1:
    inc e
    nop
    inc e
    nop
    inc e
    nop
    nop
    nop
    ld a, a
    nop
    ld a, $00
    inc e
    nop
    ld [$0000], sp
    nop
    stop
    jr nc, jr_01a_68f7

jr_01a_68f7:
    ld [hl], a
    nop
    rst $30
    nop
    ld [hl], a
    nop
    jr nc, jr_01a_68ff

jr_01a_68ff:
    stop
    ld [$0c00], sp
    nop
    xor $00
    rst $28
    nop
    xor $00
    inc c
    nop
    ld [$0000], sp
    ld c, b
    ld [$1555], sp
    ld [hl+], a
    ld [hl], $d0
    ld e, e
    ld b, c
    ld d, h
    adc c
    ldh [rNR41], a
    ld l, h
    ld b, [hl]
    push af
    pop bc
    ret nz

    inc [hl]
    inc [hl]
    ld a, [bc]
    ld a, d
    sub d
    ld e, $8d
    inc bc
    ld b, [hl]
    ld [hl], d
    inc de
    rrca
    ld c, e
    rla
    jp z, $b5ff

    rst $38
    ld [$5d7f], a
    ld a, a
    dec sp
    cp a
    rlca
    ld l, a
    nop
    ld h, $00
    add hl, bc
    sbc [hl]
    ld l, a
    ld d, [hl]
    cp $ad
    db $fd
    ld e, e
    ld a, [$feec]
    ld b, b
    ld hl, sp+$00

jr_01a_694d:
    db $e4

jr_01a_694e:
    nop
    ld hl, $0000
    ld e, l
    inc e
    rla
    rla
    rla
    rla
    or b
    inc [hl]
    scf
    scf
    ld a, a
    ld [hl], a
    ld a, b
    ld [hl], h
    nop
    nop
    ld a, c
    jr c, jr_01a_694d

    add sp, -$18
    add sp, $0c
    inc l
    db $ed
    db $ec
    cp $ee
    ld e, $2e
    ld a, a
    ld [hl], a
    ld a, a
    ld [hl], a
    inc sp
    inc a
    scf
    ccf
    sbc a
    rra
    rlca
    rlca
    nop
    nop
    ld b, b
    nop
    cp $ee
    rst $38
    xor $cc
    inc a
    db $ec
    db $fc
    ld hl, sp-$08
    pop hl
    ldh [rP1], a
    nop
    ld b, b

jr_01a_698f:
    nop
    rla
    rla
    ld d, a
    rla
    db $10
    inc d
    rla
    rla
    sbc h
    ccf
    nop
    ccf
    nop
    rrca
    ld b, b
    nop
    add sp, -$18
    jp hl


    add sp, $08
    jr z, jr_01a_698f

    add sp, $38
    db $fc
    ld bc, $00fc
    ldh a, [rLCDC]
    nop
    xor d
    nop
    ld b, c
    inc d
    xor d
    ld b, c
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    nop
    add b
    and d
    db $10
    ld c, b
    nop
    add c
    ld d, d
    ld c, b
    or h
    sub h
    ld h, b
    jr z, jr_01a_694e

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
    nop
    nop
    nop
    inc [hl]
    jr nz, jr_01a_6a03

    jr nz, jr_01a_6a05

    jr nz, jr_01a_6a07

    inc [hl]
    jr nz, jr_01a_6a1e

    jr nz, jr_01a_6a0c

    jr nz, jr_01a_6a0e

    jr nz, jr_01a_6a24

    inc b
    dec b
    ld b, $07
    inc hl
    dec d
    ld d, $17
    inc h
    dec h
    ld h, $27
    nop
    dec [hl]
    ld [hl], $30
    inc sp
    inc sp
    inc sp

jr_01a_6a03:
    inc sp
    inc sp

jr_01a_6a05:
    inc sp
    inc sp

jr_01a_6a07:
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp

jr_01a_6a0c:
    inc sp
    inc sp

jr_01a_6a0e:
    inc sp
    inc sp
    jr nz, jr_01a_6a32

    jr nz, jr_01a_6a34

    jr nz, jr_01a_6a36

    jr nz, jr_01a_6a38

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01a_6a1e:
    ld [de], a
    inc de
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01a_6a24:
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr nz, jr_01a_6a4a

    jr nz, jr_01a_6a4c

    jr nz, jr_01a_6a4e

    jr nz, jr_01a_6a50

    ld [bc], a
    inc bc

jr_01a_6a32:
    jr nz, jr_01a_6a54

jr_01a_6a34:
    ld [de], a
    inc de

jr_01a_6a36:
    jr nz, jr_01a_6a58

jr_01a_6a38:
    ld [bc], a
    inc bc
    jr nz, jr_01a_6a5c

    ld [de], a
    inc de
    jr nz, jr_01a_6a60

    jr nz, jr_01a_6a62

    ld [bc], a
    inc bc
    jr nz, jr_01a_6a66

    ld [de], a
    inc de
    jr nz, jr_01a_6a6a

jr_01a_6a4a:
    ld [bc], a
    inc bc

jr_01a_6a4c:
    jr nz, jr_01a_6a6e

jr_01a_6a4e:
    ld [de], a
    inc de

jr_01a_6a50:
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01a_6a54:
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01a_6a58:
    ld [bc], a
    inc bc
    jr nz, jr_01a_6a7c

jr_01a_6a5c:
    ld [de], a
    inc de
    jr nz, jr_01a_6a80

jr_01a_6a60:
    ld [bc], a
    inc bc

jr_01a_6a62:
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01a_6a66:
    ld [de], a
    inc de
    jr nz, jr_01a_6a8a

jr_01a_6a6a:
    ld [bc], a
    inc bc
    jr nz, jr_01a_6a8e

jr_01a_6a6e:
    ld [de], a
    inc de
    ld [bc], a
    inc bc
    jr nz, jr_01a_6a94

    ld [de], a
    inc de
    jr nz, jr_01a_6a98

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01a_6a7c:
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01a_6a80:
    jr nz, jr_01a_6aa2

    ld [bc], a
    inc bc
    jr nz, jr_01a_6aa6

    ld [de], a
    inc de
    ld [bc], a
    inc bc

jr_01a_6a8a:
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01a_6a8e:
    ld [de], a
    inc de
    jr nz, jr_01a_6ab2

    jr nz, jr_01a_6ab4

jr_01a_6a94:
    jr nz, jr_01a_6ab6

    jr nz, jr_01a_6ab8

jr_01a_6a98:
    ld [bc], a
    inc bc
    jr nz, jr_01a_6abc

    ld [de], a
    inc de
    jr nz, jr_01a_6ac0

    jr nz, jr_01a_6ac2

jr_01a_6aa2:
    jr nz, jr_01a_6ac4

    jr nz, jr_01a_6ac6

jr_01a_6aa6:
    jr nz, jr_01a_6ac8

    jr nz, jr_01a_6aca

    ld [bc], a
    inc bc
    jr nz, jr_01a_6ace

    ld [de], a
    inc de
    ld [bc], a
    inc bc

jr_01a_6ab2:
    jr nz, jr_01a_6ad4

jr_01a_6ab4:
    ld [de], a
    inc de

jr_01a_6ab6:
    jr nz, jr_01a_6ad8

jr_01a_6ab8:
    jr nz, jr_01a_6ada

    jr nz, jr_01a_6adc

jr_01a_6abc:
    jr nz, jr_01a_6ade

    jr nz, jr_01a_6ae0

jr_01a_6ac0:
    jr nz, jr_01a_6ae2

jr_01a_6ac2:
    ld [bc], a
    inc bc

jr_01a_6ac4:
    jr nz, jr_01a_6ae6

jr_01a_6ac6:
    ld [de], a
    inc de

jr_01a_6ac8:
    jr nz, jr_01a_6aea

jr_01a_6aca:
    jr nz, jr_01a_6aec

    jr nz, jr_01a_6aee

jr_01a_6ace:
    jr nz, jr_01a_6af0

    jr nz, jr_01a_6af2

    jr nz, jr_01a_6af4

jr_01a_6ad4:
    jr nz, jr_01a_6af6

    jr nz, jr_01a_6af8

jr_01a_6ad8:
    jr nz, jr_01a_6afa

jr_01a_6ada:
    ld d, h
    ld d, l

jr_01a_6adc:
    jr nz, jr_01a_6afe

jr_01a_6ade:
    ld d, [hl]
    ld d, a

jr_01a_6ae0:
    jr nz, jr_01a_6b02

jr_01a_6ae2:
    jr nz, jr_01a_6b04

    jr nz, jr_01a_6b06

jr_01a_6ae6:
    jr nz, jr_01a_6b08

    ld d, h
    ld d, l

jr_01a_6aea:
    jr nz, jr_01a_6b0c

jr_01a_6aec:
    ld d, [hl]
    ld d, a

jr_01a_6aee:
    jr nz, jr_01a_6b10

jr_01a_6af0:
    jr nz, jr_01a_6b12

jr_01a_6af2:
    ld d, h
    ld d, l

jr_01a_6af4:
    jr nz, jr_01a_6b16

jr_01a_6af6:
    ld d, [hl]
    ld d, a

jr_01a_6af8:
    jr nz, jr_01a_6b1a

jr_01a_6afa:
    jr nz, jr_01a_6b1c

    jr nz, jr_01a_6b1e

jr_01a_6afe:
    jr nz, jr_01a_6b20

    ld d, h
    ld d, l

jr_01a_6b02:
    jr nz, jr_01a_6b24

jr_01a_6b04:
    ld d, [hl]
    ld d, a

jr_01a_6b06:
    jr nz, jr_01a_6b28

jr_01a_6b08:
    jr nz, @+$22

    jr nz, jr_01a_6b2c

jr_01a_6b0c:
    jr nz, @+$22

    jr nz, jr_01a_6b30

jr_01a_6b10:
    jr nc, jr_01a_6b42

jr_01a_6b12:
    jr nc, jr_01a_6b44

    jr nc, jr_01a_6b46

jr_01a_6b16:
    jr nc, jr_01a_6b48

    inc b
    dec b

jr_01a_6b1a:
    ld b, $07

jr_01a_6b1c:
    inc hl
    dec d

jr_01a_6b1e:
    ld d, $17

jr_01a_6b20:
    jr nc, jr_01a_6b52

    ld [bc], a
    inc bc

jr_01a_6b24:
    jr nc, jr_01a_6b56

    ld [de], a
    inc de

jr_01a_6b28:
    ld hl, $0222
    inc bc

jr_01a_6b2c:
    ld sp, $1232
    inc de

jr_01a_6b30:
    ld hl, $2022
    jr nz, jr_01a_6b66

    ld [hl-], a
    jr nz, jr_01a_6b58

    jr nz, jr_01a_6b5a

    jr nz, jr_01a_6b5c

    jr nz, jr_01a_6b5e

    jr nz, jr_01a_6b60

    jr nc, jr_01a_6b72

jr_01a_6b42:
    jr nc, jr_01a_6b74

jr_01a_6b44:
    jr nc, jr_01a_6b76

jr_01a_6b46:
    jr nc, jr_01a_6b78

jr_01a_6b48:
    ld b, d
    ld b, d
    ld b, d
    ld b, d
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    inc h
    dec h

jr_01a_6b52:
    ld h, $27
    nop
    dec [hl]

jr_01a_6b56:
    ld [hl], $30

jr_01a_6b58:
    jr nc, jr_01a_6b8a

jr_01a_6b5a:
    jr nc, jr_01a_6b8c

jr_01a_6b5c:
    jr nc, jr_01a_6b8e

jr_01a_6b5e:
    jr nc, jr_01a_6b90

jr_01a_6b60:
    ld [$0909], sp
    add hl, bc
    jr jr_01a_6b7f

jr_01a_6b66:
    add hl, de
    add hl, de
    jr z, jr_01a_6b93

    ld a, [hl+]
    dec hl
    jr c, jr_01a_6b97

    ld a, [hl-]
    dec sp
    add hl, bc
    add hl, bc

jr_01a_6b72:
    add hl, bc
    inc c

jr_01a_6b74:
    add hl, de
    add hl, de

jr_01a_6b76:
    add hl, de
    inc e

jr_01a_6b78:
    db $10
    ld de, $2c29
    add hl, hl
    add hl, hl
    add hl, hl

jr_01a_6b7f:
    inc a
    jr nc, jr_01a_6bb2

    jr nc, jr_01a_6bb4

    jr nc, jr_01a_6bb6

    jr nc, jr_01a_6bb8

    jr nc, jr_01a_6bba

jr_01a_6b8a:
    jr nc, jr_01a_6bbc

jr_01a_6b8c:
    jr nc, jr_01a_6bbe

jr_01a_6b8e:
    jr nc, jr_01a_6bc0

jr_01a_6b90:
    add hl, bc
    add hl, bc
    add hl, bc

jr_01a_6b93:
    inc c
    add hl, de
    add hl, de
    add hl, de

jr_01a_6b97:
    inc e
    ld bc, $2901
    inc l
    add hl, hl
    add hl, hl
    add hl, hl
    inc a
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr nc, @+$32

jr_01a_6bb2:
    jr nc, @+$32

jr_01a_6bb4:
    jr nc, jr_01a_6be6

jr_01a_6bb6:
    jr nc, jr_01a_6be8

jr_01a_6bb8:
    ld [bc], a
    inc bc

jr_01a_6bba:
    ld [bc], a
    inc bc

jr_01a_6bbc:
    ld [de], a
    inc de

jr_01a_6bbe:
    ld [de], a
    inc de

jr_01a_6bc0:
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr nc, jr_01a_6bfa

    jr nc, jr_01a_6bfc

    jr nc, jr_01a_6bfe

    jr nc, jr_01a_6c00

    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    inc [hl]
    inc [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    inc [hl]
    inc [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld hl, $3022
    jr nc, jr_01a_6c16

    ld [hl-], a

jr_01a_6be6:
    jr nc, jr_01a_6c18

jr_01a_6be8:
    jr nc, jr_01a_6c1a

    jr nc, jr_01a_6c1c

    jr nc, jr_01a_6c1e

    jr nc, jr_01a_6c20

    jr nz, jr_01a_6c12

    jr nc, jr_01a_6c24

    jr nz, jr_01a_6c16

    jr nc, jr_01a_6c28

    jr nz, jr_01a_6c1a

jr_01a_6bfa:
    jr nz, jr_01a_6c1c

jr_01a_6bfc:
    jr nz, jr_01a_6c1e

jr_01a_6bfe:
    jr nz, jr_01a_6c20

jr_01a_6c00:
    jr nc, jr_01a_6c32

    jr nz, jr_01a_6c24

    jr nc, jr_01a_6c36

    jr nz, jr_01a_6c28

    jr nz, jr_01a_6c2a

    jr nz, jr_01a_6c2c

    jr nz, jr_01a_6c2e

    jr nz, jr_01a_6c30

    jr nz, jr_01a_6c32

jr_01a_6c12:
    jr nz, jr_01a_6c34

    jr nz, jr_01a_6c36

jr_01a_6c16:
    jr nz, jr_01a_6c38

jr_01a_6c18:
    jr nz, jr_01a_6c3a

jr_01a_6c1a:
    jr nc, jr_01a_6c4c

jr_01a_6c1c:
    jr nz, jr_01a_6c3e

jr_01a_6c1e:
    jr nc, jr_01a_6c50

jr_01a_6c20:
    jr nz, jr_01a_6c42

    jr nz, jr_01a_6c44

jr_01a_6c24:
    jr nz, jr_01a_6c46

    jr nz, jr_01a_6c48

jr_01a_6c28:
    jr nc, jr_01a_6c5a

jr_01a_6c2a:
    jr nz, jr_01a_6c4c

jr_01a_6c2c:
    jr nc, jr_01a_6c5e

jr_01a_6c2e:
    jr nz, jr_01a_6c50

jr_01a_6c30:
    jr nc, jr_01a_6c62

jr_01a_6c32:
    jr nc, jr_01a_6c64

jr_01a_6c34:
    jr nc, jr_01a_6c66

jr_01a_6c36:
    ld a, [bc]
    dec bc

jr_01a_6c38:
    ld b, d
    ld b, d

jr_01a_6c3a:
    ld a, [de]
    dec de
    ld b, e
    ld b, e

jr_01a_6c3e:
    ld c, e
    ld c, h
    jr nc, @+$32

jr_01a_6c42:
    jr nc, @+$32

jr_01a_6c44:
    ld a, [bc]
    dec bc

jr_01a_6c46:
    jr nc, jr_01a_6c78

jr_01a_6c48:
    ld a, [de]
    dec de
    ld b, d
    ld b, d

jr_01a_6c4c:
    ld c, e
    ld c, h
    ld b, e
    ld b, e

jr_01a_6c50:
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]

jr_01a_6c5a:
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]

jr_01a_6c5e:
    ld e, [hl]
    ld e, [hl]
    jr nc, jr_01a_6c92

jr_01a_6c62:
    jr nc, jr_01a_6c94

jr_01a_6c64:
    jr nc, jr_01a_6c96

jr_01a_6c66:
    jr nc, jr_01a_6c98

    jr nc, jr_01a_6c9a

    jr nc, jr_01a_6c9c

    jr nc, jr_01a_6c9e

    scf
    jr nc, jr_01a_6ca1

    jr nc, jr_01a_6ca3

    jr nc, @+$0c

    dec bc
    jr nc, jr_01a_6ca8

jr_01a_6c78:
    ld a, [de]
    dec de
    jr nc, jr_01a_6cac

    ld c, e
    ld c, h
    jr nc, jr_01a_6cb0

    jr nc, jr_01a_6cb2

    jr nc, jr_01a_6cb4

    jr nc, jr_01a_6cb6

    ld a, [bc]
    dec bc
    jr nc, jr_01a_6cba

    ld a, [de]
    dec de
    jr nc, jr_01a_6cbe

    ld c, e
    ld c, h
    jr nc, @+$32

jr_01a_6c92:
    jr nc, @+$32

jr_01a_6c94:
    add hl, sp
    ld e, a

jr_01a_6c96:
    jr nc, jr_01a_6cc8

jr_01a_6c98:
    jr nc, jr_01a_6cca

jr_01a_6c9a:
    jr nc, jr_01a_6ccc

jr_01a_6c9c:
    jr nc, jr_01a_6cce

jr_01a_6c9e:
    jr nc, jr_01a_6cd0

    inc d

jr_01a_6ca1:
    inc d
    inc d

jr_01a_6ca3:
    inc d
    inc d
    inc d
    inc d
    inc d

jr_01a_6ca8:
    inc d
    inc d
    inc d
    inc d

jr_01a_6cac:
    inc d
    inc d
    inc d
    inc d

jr_01a_6cb0:
    jr nc, jr_01a_6ce2

jr_01a_6cb2:
    jr nc, jr_01a_6ce4

jr_01a_6cb4:
    jr nc, jr_01a_6ced

jr_01a_6cb6:
    jr nc, jr_01a_6ce8

    jr nc, jr_01a_6cea

jr_01a_6cba:
    add hl, sp
    ld e, a
    jr nc, jr_01a_6cee

jr_01a_6cbe:
    jr nc, jr_01a_6cf0

    inc [hl]
    jr nz, jr_01a_6ce3

    jr nz, jr_01a_6ce5

    jr nz, jr_01a_6ce7

    inc [hl]

jr_01a_6cc8:
    jr nz, jr_01a_6cfe

jr_01a_6cca:
    jr nz, jr_01a_6cec

jr_01a_6ccc:
    jr nz, jr_01a_6cee

jr_01a_6cce:
    jr nz, jr_01a_6d04

jr_01a_6cd0:
    jr nz, jr_01a_6cf2

    ld c, l
    inc d
    jr nz, jr_01a_6cf6

    ld c, b
    inc d
    jr nz, jr_01a_6cfa

    jr nz, jr_01a_6cfc

    jr nz, jr_01a_6cfe

    jr nz, jr_01a_6d00

    inc d
    inc d

jr_01a_6ce2:
    inc d

jr_01a_6ce3:
    inc d

jr_01a_6ce4:
    inc d

jr_01a_6ce5:
    inc d
    inc d

jr_01a_6ce7:
    inc d

jr_01a_6ce8:
    ld c, l
    inc d

jr_01a_6cea:
    inc d
    ld c, [hl]

jr_01a_6cec:
    ld c, b

jr_01a_6ced:
    inc d

jr_01a_6cee:
    inc d
    ld c, d

jr_01a_6cf0:
    inc d
    ld c, [hl]

jr_01a_6cf2:
    jr nz, jr_01a_6d14

    inc d
    ld c, d

jr_01a_6cf6:
    jr nz, jr_01a_6d18

    jr nz, jr_01a_6d1a

jr_01a_6cfa:
    jr nz, jr_01a_6d1c

jr_01a_6cfc:
    jr nz, jr_01a_6d1e

jr_01a_6cfe:
    jr nz, jr_01a_6d20

jr_01a_6d00:
    jr nc, jr_01a_6d32

    jr nc, jr_01a_6d34

jr_01a_6d04:
    jr nc, jr_01a_6d36

    jr nc, jr_01a_6d38

    jr nc, jr_01a_6d3a

    ld hl, $3022
    jr nc, jr_01a_6d40

    ld [hl-], a
    jr nc, jr_01a_6d42

    jr nc, jr_01a_6d44

jr_01a_6d14:
    jr nc, jr_01a_6d46

    jr nc, jr_01a_6d48

jr_01a_6d18:
    jr nc, jr_01a_6d4a

jr_01a_6d1a:
    ld [bc], a
    inc bc

jr_01a_6d1c:
    jr nc, jr_01a_6d4e

jr_01a_6d1e:
    ld [de], a
    inc de

jr_01a_6d20:
    jr nc, jr_01a_6d52

    jr nc, jr_01a_6d54

    jr nc, jr_01a_6d56

    jr nc, jr_01a_6d58

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr nc, jr_01a_6d62

jr_01a_6d32:
    jr nc, jr_01a_6d64

jr_01a_6d34:
    jr nc, jr_01a_6d66

jr_01a_6d36:
    jr nc, jr_01a_6d68

jr_01a_6d38:
    ld [bc], a
    inc bc

jr_01a_6d3a:
    jr nc, jr_01a_6d6c

    ld [de], a
    inc de
    jr nc, jr_01a_6d70

jr_01a_6d40:
    ld [bc], a
    inc bc

jr_01a_6d42:
    jr nc, jr_01a_6d74

jr_01a_6d44:
    ld [de], a
    inc de

jr_01a_6d46:
    jr nc, jr_01a_6d78

jr_01a_6d48:
    ld [bc], a
    inc bc

jr_01a_6d4a:
    jr nc, jr_01a_6d7c

    ld [de], a
    inc de

jr_01a_6d4e:
    jr nc, jr_01a_6d80

    jr nc, jr_01a_6d82

jr_01a_6d52:
    ld [bc], a
    inc bc

jr_01a_6d54:
    jr nc, jr_01a_6d86

jr_01a_6d56:
    ld [de], a
    inc de

jr_01a_6d58:
    jr nc, jr_01a_6d8a

    jr nc, jr_01a_6d8c

    jr nc, jr_01a_6d8e

    jr nc, jr_01a_6d90

    ld [bc], a
    inc bc

jr_01a_6d62:
    ld [bc], a
    inc bc

jr_01a_6d64:
    ld [de], a
    inc de

jr_01a_6d66:
    ld [de], a
    inc de

jr_01a_6d68:
    jr nc, jr_01a_6d9a

    jr nc, jr_01a_6d9c

jr_01a_6d6c:
    jr nc, jr_01a_6d9e

    jr nc, jr_01a_6da0

jr_01a_6d70:
    ld [bc], a
    inc bc
    jr nc, jr_01a_6da4

jr_01a_6d74:
    ld [de], a
    inc de
    jr nc, jr_01a_6da8

jr_01a_6d78:
    jr nc, jr_01a_6daa

    jr nc, jr_01a_6dac

jr_01a_6d7c:
    jr nc, jr_01a_6dae

    jr nc, jr_01a_6db0

jr_01a_6d80:
    jr nc, jr_01a_6db2

jr_01a_6d82:
    ld [bc], a
    inc bc
    jr nc, @+$32

jr_01a_6d86:
    ld [de], a
    inc de
    jr nc, jr_01a_6dba

jr_01a_6d8a:
    ld [bc], a
    inc bc

jr_01a_6d8c:
    jr nc, jr_01a_6dbe

jr_01a_6d8e:
    ld [de], a
    inc de

jr_01a_6d90:
    jr nc, @+$1f

    ld e, $1e
    dec e
    dec l
    ld l, $2e
    dec l
    dec l

jr_01a_6d9a:
    ld l, $2e

jr_01a_6d9c:
    dec l
    dec l

jr_01a_6d9e:
    ld l, $2e

jr_01a_6da0:
    ld e, $1e
    ld e, $1e

jr_01a_6da4:
    ld l, $2e
    ld l, $2e

jr_01a_6da8:
    ld l, $2e

jr_01a_6daa:
    ld l, $2e

jr_01a_6dac:
    ld l, $2e

jr_01a_6dae:
    ld l, $2e

jr_01a_6db0:
    ld e, $1e

jr_01a_6db2:
    rra
    jr nc, @+$30

    ld l, $2f
    rra
    ld l, $2e

jr_01a_6dba:
    cpl
    cpl
    ld l, $2e

jr_01a_6dbe:
    cpl
    cpl
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld a, $0e
    ld l, $2e
    ld c, $2d
    ld l, $2e
    dec l
    dec l
    ld l, $2e
    dec l
    dec l
    ld l, $2e
    dec l
    dec l
    ld l, $2e
    dec l
    dec l
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    cpl
    cpl
    ld l, $2e
    cpl
    cpl
    ld l, $2e
    cpl
    cpl
    ld l, $2e
    cpl
    cpl
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    rrca
    ld a, $2e
    ld l, $2f
    rrca
    dec l
    dec l
    ld l, $2e
    dec l
    dec l
    ld l, $2e
    dec l
    dec a
    ld a, $3e
    dec a
    ld a, $3e
    ld a, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $3e
    ld a, $3e
    ld a, $3e
    ld a, $3e
    ld a, $2e
    ld l, $2f
    cpl
    ld l, $2e
    cpl
    cpl
    ld a, $3e
    ccf
    cpl
    ld a, $3e
    ld a, $3f
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld b, b
    ld b, c
    ld a, $3e
    ld b, b
    ld b, c
    ld a, $3e
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    ld [bc], a
    inc bc
    jr nc, jr_01a_6e8c

    ld [de], a
    inc de
    jr nc, jr_01a_6e90

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr nc, jr_01a_6e9a

    ld [bc], a
    inc bc
    jr nc, jr_01a_6e9e

    ld [de], a
    inc de
    ld e, $1e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld e, $1e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e

jr_01a_6e8c:
    ld l, $2e
    ld l, $2e

jr_01a_6e90:
    ld [bc], a
    inc bc
    jr nc, jr_01a_6ec4

    ld [de], a
    inc de
    jr nc, jr_01a_6ec8

    ld [bc], a
    inc bc

jr_01a_6e9a:
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01a_6e9e:
    ld [de], a
    inc de
    jr nc, jr_01a_6ed2

    ld [bc], a
    inc bc
    jr nc, jr_01a_6ed6

    ld [de], a
    inc de
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    ld e, $1e
    rra
    jr nc, jr_01a_6ee3

    ld l, $2f
    rra
    ld hl, $2f22
    cpl
    ld sp, $2f32
    cpl
    ld c, c
    inc d
    inc d
    inc d

jr_01a_6ec4:
    inc d
    inc d
    inc d
    inc d

jr_01a_6ec8:
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    jr nc, jr_01a_6f02

jr_01a_6ed2:
    ld c, c
    ld c, c
    jr nc, jr_01a_6f06

jr_01a_6ed6:
    ld c, b
    inc d
    jr nc, jr_01a_6f0a

    ld c, b
    inc d
    jr nc, jr_01a_6f0e

    ld c, b
    inc d
    ld c, c
    ld c, c
    ld c, c

jr_01a_6ee3:
    ld c, c
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    ld l, $2e

jr_01a_6f02:
    ld l, $2e
    ld l, $2e

jr_01a_6f06:
    ld l, $2e
    ld a, $3e

jr_01a_6f0a:
    ld b, b
    ld b, c
    ld a, $3e

jr_01a_6f0e:
    ld b, b
    ld b, c
    jr nc, @+$32

    ld c, b
    inc d
    jr nc, @+$32

    ld c, b
    inc d
    jr nc, jr_01a_6f4a

    ld c, b
    inc d
    jr nc, jr_01a_6f4e

    ld c, b
    inc d
    ld c, l
    inc d
    inc d
    inc d
    ld c, b
    inc d
    inc d
    inc d
    ld c, b
    inc d
    inc d
    inc d
    ld c, b
    inc d
    inc d
    inc d
    jr nc, @+$32

    jr nc, @+$32

    ld d, d
    jr nc, jr_01a_6f67

    jr nc, jr_01a_6f8b

    jr nc, jr_01a_6f6b

    jr nc, jr_01a_6f6d

    jr nc, jr_01a_6f6f

    jr nc, jr_01a_6f71

    jr nc, jr_01a_6f73

    jr nc, jr_01a_6f75

    jr nc, jr_01a_6f77

    ld d, e
    jr nc, jr_01a_6f7a

jr_01a_6f4a:
    jr nc, jr_01a_6f9f

    jr nc, jr_01a_6f7e

jr_01a_6f4e:
    jr nc, jr_01a_6f80

    jr nc, jr_01a_6fa2

    ld d, b
    jr nc, jr_01a_6f85

    jr nc, jr_01a_6f87

    jr nc, jr_01a_6f89

    jr nc, jr_01a_6f8b

    jr nc, jr_01a_6f8d

    jr nc, jr_01a_6f8f

    jr nc, jr_01a_6f91

    jr nc, jr_01a_6f93

    jr nc, jr_01a_6f95

    jr nc, jr_01a_6f97

jr_01a_6f67:
    jr nc, jr_01a_6f99

    jr nc, jr_01a_6f9b

jr_01a_6f6b:
    jr nc, jr_01a_6f9d

jr_01a_6f6d:
    ld d, c
    ld d, c

jr_01a_6f6f:
    jr nc, jr_01a_6fb9

jr_01a_6f71:
    inc d
    inc d

jr_01a_6f73:
    inc d
    ld c, b

jr_01a_6f75:
    inc d
    inc d

jr_01a_6f77:
    inc d
    ld c, b
    inc d

jr_01a_6f7a:
    inc d
    inc d
    ld c, b
    inc d

jr_01a_6f7e:
    inc d
    inc d

jr_01a_6f80:
    inc d
    inc d
    inc d
    ld c, d
    inc d

jr_01a_6f85:
    inc d
    inc d

jr_01a_6f87:
    ld c, d
    inc d

jr_01a_6f89:
    inc d
    inc d

jr_01a_6f8b:
    ld c, d
    inc d

jr_01a_6f8d:
    inc d
    inc d

jr_01a_6f8f:
    ld c, d
    ld c, c

jr_01a_6f91:
    ld c, c
    ld c, c

jr_01a_6f93:
    ld c, c
    ld c, b

jr_01a_6f95:
    inc d
    inc d

jr_01a_6f97:
    inc d
    ld c, b

jr_01a_6f99:
    inc d
    inc d

jr_01a_6f9b:
    inc d
    ld c, b

jr_01a_6f9d:
    inc d
    inc d

jr_01a_6f9f:
    inc d
    inc d
    inc d

jr_01a_6fa2:
    inc d
    ld c, [hl]
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, c
    inc d
    inc d
    inc d
    inc d
    inc d

jr_01a_6fb9:
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld c, b
    inc d
    inc d
    ld c, [hl]
    ld c, b
    inc d
    inc d
    ld c, d
    ld c, b
    inc d
    inc d
    ld c, d
    ld c, b
    inc d
    inc d
    ld c, d
    ld c, c
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    inc d
    inc d
    inc d
    ld c, d
    ld hl, $2e22
    ld l, $31
    ld [hl-], a
    ld l, $2e
    ld l, $2e
    rrca
    ld a, $2e
    ld l, $2f
    rrca
    dec e
    ld e, $1e
    rra
    dec l
    ld l, $2e
    cpl
    dec l
    ld l, $2e
    cpl
    dec a
    ld a, $3e
    ccf
    ld b, h
    ld b, l
    ld b, h
    ld b, l
    ld b, [hl]
    ld b, a
    ld b, [hl]
    ld b, a
    ld b, h
    ld b, l
    ld b, h
    ld b, l
    ld b, [hl]
    ld b, a
    ld b, [hl]
    ld b, a
    ld e, b
    ld e, c
    jr nc, jr_01a_7044

    ld e, d
    ld e, e
    jr nc, jr_01a_7048

    jr nc, jr_01a_704a

    jr nc, jr_01a_704c

    jr nc, jr_01a_704e

    jr nc, jr_01a_7050

    jr nc, jr_01a_7052

    jr nc, jr_01a_7054

    jr nc, jr_01a_7056

    jr nc, jr_01a_7058

    ld e, b
    ld e, c
    jr nc, jr_01a_705c

    ld e, d
    ld e, e
    jr nc, jr_01a_7060

    dec c
    ld c, a
    jr nc, jr_01a_7064

    ld e, h
    ld e, l
    jr nc, jr_01a_7068

    jr nc, jr_01a_706a

    jr nc, jr_01a_706c

    jr nc, jr_01a_706e

    jr nc, jr_01a_7070

    jr nc, jr_01a_7072

    jr nc, jr_01a_7074

jr_01a_7044:
    jr nc, jr_01a_7076

    jr nc, jr_01a_7078

jr_01a_7048:
    dec c
    ld c, a

jr_01a_704a:
    jr nc, jr_01a_707c

jr_01a_704c:
    ld e, h
    ld e, l

jr_01a_704e:
    jr nc, jr_01a_7080

jr_01a_7050:
    inc d
    ld c, d

jr_01a_7052:
    jr nc, jr_01a_7084

jr_01a_7054:
    inc d
    ld c, d

jr_01a_7056:
    jr nc, jr_01a_7088

jr_01a_7058:
    inc d
    ld c, d
    jr nc, jr_01a_708c

jr_01a_705c:
    inc d
    ld c, d
    jr nc, jr_01a_7090

jr_01a_7060:
    inc d
    ld c, [hl]
    jr nc, jr_01a_7094

jr_01a_7064:
    inc d
    ld c, d
    jr nc, jr_01a_7098

jr_01a_7068:
    inc d
    ld c, d

jr_01a_706a:
    jr nc, jr_01a_709c

jr_01a_706c:
    inc d
    ld c, d

jr_01a_706e:
    jr nc, jr_01a_70a0

jr_01a_7070:
    jr nc, jr_01a_70a2

jr_01a_7072:
    ld c, l
    inc d

jr_01a_7074:
    jr nc, jr_01a_70a6

jr_01a_7076:
    ld c, b
    inc d

jr_01a_7078:
    jr nc, jr_01a_70aa

    ld c, b
    inc d

jr_01a_707c:
    jr nc, jr_01a_70ae

    ld c, b
    inc d

jr_01a_7080:
    ld b, h
    ld b, l
    inc d
    inc d

jr_01a_7084:
    ld b, [hl]
    ld b, a
    inc d
    inc d

jr_01a_7088:
    ld b, h
    ld b, l
    inc d
    inc d

jr_01a_708c:
    ld b, [hl]
    ld b, a
    inc d
    inc d

jr_01a_7090:
    inc d
    inc d
    inc d
    inc d

jr_01a_7094:
    inc d
    inc d
    inc d
    inc d

jr_01a_7098:
    ld b, h
    ld b, l
    ld b, h
    ld b, l

jr_01a_709c:
    ld b, [hl]
    ld b, a
    ld b, [hl]
    ld b, a

jr_01a_70a0:
    ld b, h
    ld b, l

jr_01a_70a2:
    ld b, h
    ld b, l
    ld b, [hl]
    ld b, a

jr_01a_70a6:
    ld b, [hl]
    ld b, a
    inc d
    inc d

jr_01a_70aa:
    inc d
    inc d
    inc d
    inc d

jr_01a_70ae:
    inc d
    inc d
    ld c, c
    ld c, c
    ld c, b
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld c, c
    ld c, c
    ld c, b
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld b, h
    ld b, l
    inc d
    inc d
    ld b, [hl]
    ld b, a
    inc d
    inc d
    ld b, h
    ld b, l
    inc d
    inc d
    ld b, [hl]
    ld b, a
    ld c, c
    ld c, c
    ld b, h
    ld b, l
    inc d
    inc d
    ld b, [hl]
    ld b, a
    inc d
    inc d
    ld b, h
    ld b, l
    inc d
    inc d
    ld b, [hl]
    ld b, a
    ld c, b
    inc d
    inc d
    inc d
    ld c, b
    inc d
    inc d
    inc d
    ld b, h
    ld b, l
    ld b, h
    ld b, l
    ld b, [hl]
    ld b, a
    ld b, [hl]
    ld b, a
    ld c, b
    inc d
    inc d
    ld c, d
    ld c, b
    inc d
    inc d
    ld c, d
    ld c, b
    inc d
    inc d
    ld c, d
    ld c, b
    inc d
    inc d
    ld c, d
    dec e
    ld e, $1e
    ld e, $2d
    ld l, $2e
    ld l, $2d
    ld l, $2e
    ld l, $2d
    ld l, $2e
    ld l, $1e
    rra
    inc d
    inc d
    ld l, $2f
    inc d
    inc d
    ld l, $2f
    inc d
    inc d
    ld l, $2f
    inc d
    inc d
    inc d
    inc d
    dec e
    ld e, $14
    inc d
    dec l
    ld l, $14
    inc d
    dec l
    ld l, $14
    inc d
    dec l
    ld l, $1e
    ld e, $1e
    rra
    ld l, $2e
    ld l, $2f
    ld l, $2e
    ld l, $2f
    ld l, $2e
    ld l, $2f
    dec l
    ld l, $2e
    ld l, $2d
    ld l, $2e
    ld l, $2d
    ld l, $2e
    ld l, $3d
    ld a, $3e
    ld a, $2e
    cpl
    inc d
    inc d
    ld l, $2f
    inc d
    inc d
    ld l, $2f
    inc d
    inc d
    ld a, $3f
    inc d
    inc d
    inc d
    inc d
    dec l
    ld l, $14
    inc d
    dec l
    ld l, $14
    inc d
    dec l
    ld l, $14
    inc d
    dec a
    ld a, $2e
    ld l, $2e
    cpl
    ld l, $2e
    ld l, $2f
    ld l, $2e
    ld l, $2f
    ld a, $3e
    ld a, $3f
    jr nc, jr_01a_71c2

    jr nc, jr_01a_71c4

    jr nc, jr_01a_71c6

    jr nc, jr_01a_71c8

    ld d, h
    ld d, l
    ld d, h
    ld d, l
    ld d, [hl]
    ld d, a
    ld d, [hl]
    ld d, a
    ld d, h
    ld d, l
    ld d, h
    ld d, l
    ld d, [hl]
    ld d, a
    ld d, [hl]
    ld d, a
    jr nc, jr_01a_71da

    jr nc, jr_01a_71dc

    jr nc, jr_01a_71de

    jr nc, jr_01a_71e0

    jr nc, jr_01a_71e2

    ld d, h
    ld d, l
    jr nc, jr_01a_71e6

    ld d, [hl]
    ld d, a
    jr nc, jr_01a_71ea

    ld d, h
    ld d, l
    jr nc, jr_01a_71ee

    ld d, [hl]
    ld d, a
    ld d, h
    ld d, l

jr_01a_71c2:
    jr nc, jr_01a_71f4

jr_01a_71c4:
    ld d, [hl]
    ld d, a

jr_01a_71c6:
    jr nc, jr_01a_71f8

jr_01a_71c8:
    ld d, h
    ld d, l
    jr nc, jr_01a_71fc

    ld d, [hl]
    ld d, a
    jr nc, jr_01a_7200

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01a_71da:
    nop
    nop

jr_01a_71dc:
    nop
    nop

jr_01a_71de:
    nop
    nop

jr_01a_71e0:
    ldh a, [rP1]

jr_01a_71e2:
    ldh a, [rP1]
    ldh a, [rP1]

jr_01a_71e6:
    ldh a, [rP1]
    rrca
    nop

jr_01a_71ea:
    rrca
    nop
    rrca
    nop

jr_01a_71ee:
    rrca
    nop
    rst $38
    rst $38
    nop
    nop

jr_01a_71f4:
    rst $38
    nop
    rst $38
    nop

jr_01a_71f8:
    rst $38
    nop
    rst $38
    nop

jr_01a_71fc:
    rst $38
    nop
    rst $38
    nop

jr_01a_7200:
    nop
    nop
    nop
    nop
    rlca
    rlca
    inc b
    inc b
    db $fc
    db $fc
    add h
    add h
    add h
    add h
    adc l
    add h
    ccf
    ccf
    ld hl, $e121
    pop hl
    ld hl, $2121
    ld hl, $2161
    pop hl
    ld hl, $21e1
    xor d
    jr nz, jr_01a_72a0

    ld e, b
    cp $66
    rst $28
    sub l
    db $e3
    ld a, l
    ret nc

    xor a
    rst $20
    ld a, a
    rst $38
    ld sp, hl
    xor [hl]
    inc b
    ld e, a
    ld a, [de]
    ei
    ld h, a
    pop af
    xor a
    ld b, [hl]
    cp a
    sbc a
    pop af
    or $ce
    sbc l
    ld hl, sp-$55
    ld bc, $0054
    xor d
    inc bc
    ld e, a
    ld c, $b4
    ld e, $4e
    dec c
    cp h
    ld l, $7e
    cpl
    ld bc, $0200
    nop
    rst $38
    rst $38
    rst $38
    add c
    rst $38
    add c
    rst $38
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    add b
    ret nz

    cp a
    ret nz

    and b
    ret nz

    and b
    ret nz

    and b
    ret nz

    and b
    ret nz

    and b
    rst $38
    rst $38
    rst $38
    ld bc, $fd03
    inc bc
    dec b
    inc bc
    dec b
    inc bc
    dec b
    inc bc
    dec b
    inc bc
    dec b
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    add a
    add a
    add a
    add a
    add a
    add h
    add a
    add h
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
    ccf
    rst $38
    ccf

jr_01a_72a0:
    rst $38
    rst $38
    add b
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    rst $38
    rst $38
    ld bc, $fd01
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    ld l, d
    ret nz

    push de
    ld b, b
    ld l, d
    ret nz

    push af
    ld [hl], b
    xor d
    ld a, b
    ld [hl], l
    or b
    cp [hl]
    ld [hl], h
    ld a, l
    db $f4
    nop
    nop
    nop
    nop
    nop
    nop

jr_01a_72d6:
    nop
    nop
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
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    sbc a
    add h
    cp a
    add h
    rst $38
    add h
    rst $38
    add a
    db $fc
    add a
    db $fc
    rst $38
    add b
    rst $38
    add b
    rst $38
    nop
    inc a
    nop
    adc c
    nop
    ld h, b
    nop
    rst $30
    nop
    rst $20
    nop
    rst $20
    nop
    sbc e
    nop
    call c, Call_01a_66f9
    pop de
    cp [hl]
    rst $30
    ld c, d
    push hl
    sbc e
    db $eb
    rst $18
    rst $38
    sbc e
    rst $38
    ld d, l
    ld [hl], l
    ld hl, $66df
    rrca
    ld sp, hl
    and d
    rst $18
    xor e
    push de
    db $db
    rst $30
    rst $38
    reti


    rst $38
    ld [$667f], a
    xor a
    scf
    ld h, a
    jr c, jr_01a_72d6

    inc a
    scf
    ld e, a
    db $d3
    inc a
    add hl, hl
    ld e, h
    sub a
    cpl
    ld e, d
    dec b
    add c
    rst $38
    add c
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    ld b, d
    nop
    add c
    nop
    ret nz

    and b
    ret nz

    cp a
    rst $38
    add b
    rst $38
    rst $38
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    rst $38
    inc bc
    dec b
    inc bc
    db $fd
    rst $38
    ld bc, $ffff
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    rst $38
    rst $38
    add a
    add h
    add a
    add h
    add a
    add h
    add a
    add h
    add a
    add h
    add a
    add h
    add a
    add h
    rst $38
    rst $38
    pop hl
    ccf
    pop hl
    ccf
    pop hl
    ccf
    pop hl
    ccf
    pop hl
    ccf
    pop hl
    ccf
    pop hl
    ccf
    rst $38
    rst $38
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    cp a
    add b
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    or $ec
    push hl
    inc e
    ld c, $f8
    db $eb
    db $fc
    inc c
    ld a, [$f41b]
    or $e8
    and l
    ld d, b
    add b
    inc e
    add b
    ld c, $80
    rlca
    add b
    inc bc
    add b
    ld bc, $0080
    add b
    nop
    rst $38
    nop
    rst $38
    nop
    add b
    nop
    add b
    nop
    add b
    ld bc, $0380
    add b
    rlca
    add b
    ld c, $80
    inc e
    xor d
    ld d, l
    ld d, l
    xor d
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    xor d
    ld d, l
    ld d, l
    xor d
    ldh a, [rP1]
    db $fc
    inc c
    rst $38
    ccf
    ldh [$3f], a
    ld l, a
    ld a, a
    ld l, h
    ld a, [hl]
    add hl, hl
    inc a
    ld a, [hl+]
    jr c, @+$09

    rlca
    dec b
    ld b, $05
    ld b, $05
    ld b, $05
    ld b, $05
    ld b, $05
    ld b, $05
    ld b, $ff
    ldh [$bf], a
    ld h, b
    cp a
    ld h, b
    cp a
    ld h, b
    cp a
    ld h, b
    cp a
    ld h, b
    cp a
    ld h, b
    cp a
    ld h, b
    and a
    add [hl]
    sbc l
    add e
    rlca
    nop
    add e
    inc c
    ld d, l
    cp a
    xor e
    ld a, a
    rst $10
    cp $ff
    ld a, b
    ld bc, $3601
    ld [hl], $7a
    ld c, [hl]
    ld sp, $142f
    rra
    ld [hl+], a
    dec sp
    ld h, b
    ld a, a
    sbc h
    sbc [hl]
    rst $38
    rst $38
    cp a
    add b
    cp a
    add b
    rst $38
    rst $38
    add b
    rst $38
    adc a
    rst $38
    ld hl, sp-$10
    rst $28
    ret nc

    rst $38
    rst $38
    db $fd
    ld bc, $01fd
    rst $38
    rst $38
    ld bc, $f1ff
    rst $38
    rra
    rrca
    rst $30
    dec bc
    rst $38
    rst $38
    nop
    nop
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
    nop
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
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
    rst $38
    rst $38
    add b
    add b
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    cp a
    rst $38
    add b
    rst $38
    rst $38
    ld bc, $fd01
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
    ld bc, $8080

jr_01a_74c2:
    ld l, h
    ld l, h
    ld d, [hl]
    ld a, d
    adc h
    db $f4
    jr z, jr_01a_74c2

    ld b, h
    call c, $fe06
    cp c
    ld a, c
    ld bc, $0138
    ld [hl], b
    ld bc, $01e0
    ret nz

    ld bc, $0180
    nop
    ld bc, $ff00
    nop
    rst $38
    nop
    ld bc, $0100
    nop
    ld bc, $0180
    ret nz

    ld bc, $01e0
    ld [hl], b
    ld bc, $aa38
    nop
    ld d, l
    nop
    xor d
    inc d
    nop
    ld d, l
    xor d
    ld b, c
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
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
    rst $38
    rst $38
    dec e
    inc bc
    dec c
    inc bc
    dec b
    inc bc
    rst $38
    rst $38
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
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
    add d
    ldh a, [$80]
    db $fc
    xor e
    rst $38
    push af
    ld a, a
    sbc e
    ld a, a
    rst $20
    ld e, $f9
    rlca
    rst $38
    nop
    xor e
    sbc e
    ld d, h
    ld a, h
    inc sp
    ccf
    ld d, b
    ld a, b
    ret c

    cp b
    db $ec
    cp h
    db $e3
    xor e
    db $fc
    sbc a
    ret nz

    add b
    ret nz

    add b
    ret nz

    add b
    ret nz

    add b
    ret nz

    add b
    ret nz

    add b
    ret nz

    add b
    ret nz

    add b
    inc bc
    ld bc, $0103
    inc bc
    ld bc, $0103
    inc bc
    ld bc, $0103
    inc bc
    ld bc, $0103
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ret nz

    cp a
    rst $38
    add b
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    add b
    ret nz

    cp a
    rst $38
    rst $38
    rst $38
    rst $38
    inc bc
    db $fd
    rst $38
    ld bc, $fd03
    inc bc
    db $fd
    rst $38
    ld bc, $fd03
    rst $38
    rst $38
    rst $38
    rst $38
    cp a
    add b
    cp a
    sbc a
    or b
    sub b
    or b
    sub b
    cp a
    sbc a
    ld a, a
    ret nz

    ccf
    rst $38
    rst $38
    rst $38
    ld sp, hl
    rlca
    ld sp, hl
    rst $38
    add hl, bc
    rrca
    add hl, bc
    rrca
    ld sp, hl
    rst $38
    ld a, [$fc07]
    rst $38
    db $d3
    reti


    ld a, [hl+]
    ld a, $cc
    db $fc
    ld a, [bc]
    ld e, $1b
    dec e
    scf
    dec a
    rst $00
    push de
    ccf
    ld sp, hl
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    nop
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    sub [hl]
    ld b, c
    ld l, c
    add d
    sub [hl]
    ld b, c
    ld l, c
    add d
    sub [hl]
    ld b, c
    ld l, c
    add d
    sub [hl]
    ld b, c
    ld l, c
    add d
    rst $38
    rst $38
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    jp $c3ff


    rst $38
    rst $18
    ld b, d
    rst $18
    ld b, d
    ld a, [hl]
    ld a, [hl]
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    nop
    nop
    ldh a, [rP1]
    ldh a, [$30]
    db $fc
    db $fc
    inc b
    db $fc
    rst $30
    cp $37
    ld a, [hl]
    sub a
    inc a
    ld d, a
    inc e
    rst $38
    ldh [$1f], a
    rra
    ldh [$e0], a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    cp $ff
    db $e4
    rst $38
    rra
    ld [$e938], a
    inc a
    db $ec
    ld a, [hl]
    rst $28
    ld a, a
    jr nz, jr_01a_7699

    ccf
    ccf
    rrca
    inc c
    rrca
    nop
    ld d, h
    inc e
    sub h
    inc a
    ld [hl], $7e
    or $fe
    rlca
    db $fc
    rst $38
    db $fc
    ccf
    jr nc, jr_01a_767e

    nop
    add b
    rst $38
    cp a
    rst $38
    or e
    rst $38
    xor l
    rst $38
    xor l
    rst $38
    or e
    rst $38
    cp a
    rst $38

jr_01a_767e:
    add b
    rst $38
    ld bc, $fdff
    rst $38
    call $b5ff
    rst $38
    or l
    rst $38
    call $fdff
    rst $38
    ld bc, $ffff
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b

jr_01a_7699:
    rst $38
    add b
    rst $38
    xor b
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $15ff
    rst $38
    rst $38
    rst $38
    pop hl
    ld hl, $3fff
    pop hl
    ccf
    pop hl
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $01ff
    rst $38
    push de
    xor e
    ld b, h
    ld e, [hl]
    sbc b
    dec a
    ld e, l
    cp d
    inc a
    ld d, a
    ld a, h
    xor a
    dec sp
    rst $30
    rst $38
    pop hl
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    inc h
    rst $20
    inc h
    jr @+$01

    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    cp l
    rst $20
    and l
    rst $20

jr_01a_76ea:
    sbc c
    rst $38
    add c
    add c
    rst $38
    rst $38
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    rst $38
    jr jr_01a_76ea

    inc h
    rst $38
    ld b, e
    cp $5a
    and $66
    pop hl
    ld hl, $40c1
    pop bc
    ld b, b
    rst $38
    ld h, b
    sbc a
    sbc b
    and a
    xor h
    ld d, a
    ld c, h
    rla
    inc c
    xor e
    adc h
    ld a, c
    ld a, [hl]
    ld b, l
    ld b, [hl]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    rrca
    nop
    scf
    ld [$5cbf], sp
    rst $38
    rst $38
    rst $38
    rst $38
    add c
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    cp l
    add c
    add c
    add c
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    rst $38
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    rst $38
    rst $38
    ld a, l
    inc bc
    dec a
    inc bc
    dec e
    inc bc
    ret nz

    ld b, b
    ld a, a
    ret nz

    ld a, a
    ldh [$7f], a
    rst $38
    push de
    ld a, a
    ld l, d
    rst $38
    dec [hl]
    rst $38
    rra
    rst $38
    inc bc
    ld [bc], a
    cp $03
    cp $07
    cp $ff
    ld d, a
    cp $ac
    rst $38
    ld d, h
    rst $38
    ld hl, sp-$01
    rst $38
    nop
    add c
    nop
    add c
    inc a
    nop
    cp l
    add c
    inc a
    add c
    inc a
    add c
    nop
    nop
    rst $38
    rst $38
    ld a, a
    add b
    add b
    ld l, a
    cpl
    rst $38
    ld a, a
    rst $38
    ld a, a
    rst $38
    cp a
    rst $38
    rlca
    rst $38
    ld hl, sp+$00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0101
    jr nz, @+$32

    ld bc, $2001
    jr nc, @+$23

    ld sp, $0101
    ld hl, $0131
    ld bc, $0101
    ld sp, $0131
    ld bc, $3030
    ld sp, $0131
    ld bc, $3030
    ld bc, $0101
    ld bc, $2222
    ld bc, $5201
    ld d, d
    ld bc, $5201
    ld d, d
    ld bc, $2201
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld bc, $5201
    ld d, d
    ld bc, $5201
    ld d, d
    ld bc, $2201
    ld [hl+], a
    ld bc, $5301
    ld d, h
    ld d, e
    ld d, h
    ld [hl], $26
    ld [hl], $26
    ld d, e
    ld d, h
    ld d, e
    ld d, h
    ld [hl], $26
    ld [hl], $26
    ld d, e
    ld d, h
    ld d, e
    ld d, h
    ld [hl], $26
    ld [hl], $26
    ld bc, $0101
    ld bc, $0101
    ld bc, $4201
    ld d, d
    ld d, d
    ld b, d
    ld b, d
    ld d, d
    ld d, d
    ld b, d
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0605
    ld bc, $1501
    ld d, $01
    ld bc, $0f07
    ld bc, $1701
    rra
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0605
    dec b
    ld b, $15
    ld d, $15
    ld d, $07
    rrca
    rlca
    rrca
    rla
    rra
    rla
    rra
    dec b
    ld b, $2d
    ld l, $15
    ld d, $2b
    inc l
    rlca
    rrca
    dec hl
    inc l
    rla
    rra
    dec hl
    inc l
    dec b
    ld b, $01
    ld bc, $1615
    ld bc, $0701
    rrca
    ld bc, $1701
    rra
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $2101
    ld hl, $0101
    jr nz, jr_01a_78e8

    ld bc, $2101
    ld hl, $0101
    jr nz, @+$22

    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    dec c
    ld c, $01
    ld bc, $1e1d
    ld bc, $0101
    ld bc, $0a09
    ld bc, $1901
    ld a, [de]

jr_01a_78e8:
    ld bc, $0101
    ld bc, $0101
    ld bc, $2b01
    inc l
    dec b
    ld b, $2b
    inc l
    dec d
    ld d, $2b
    inc l
    rlca
    rrca
    dec hl
    inc l
    rla
    rra
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld e, [hl]
    ld e, [hl]
    ld bc, $5e01
    ld e, [hl]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0101
    ld bc, $3121
    ld bc, $2101
    ld sp, $5e5e
    add hl, bc
    ld a, [bc]
    ld e, [hl]
    ld e, [hl]
    add hl, de
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    add hl, bc
    ld a, [bc]
    dec hl
    inc l
    add hl, de
    ld a, [de]
    dec hl
    inc l
    add hl, bc
    ld a, [bc]
    dec hl
    inc l
    add hl, de
    ld a, [de]
    dec hl
    inc l
    ld hl, $0931
    ld a, [bc]
    ld hl, $1931
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $2101
    ld hl, $0101
    jr nz, jr_01a_79ae

    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]

jr_01a_79ae:
    add hl, de
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld de, $1111
    ld de, $1111
    ld de, $0111
    ld bc, $0a09
    ld bc, $1901
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0b01
    inc c
    ld bc, $1b01
    inc e
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0202
    ld [bc], a
    ld [bc], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    dec e
    ld e, $01
    ld bc, $1e1d
    ld bc, $1d01
    ld e, $01
    ld bc, $1212
    ld bc, $0b01
    inc c
    ld d, a
    ld d, a
    dec de
    inc e
    ld e, c
    ld e, c
    ld bc, $0101
    ld bc, $0101
    ld bc, $1d01
    ld e, $01
    ld bc, $1e1d
    ld bc, $1d01
    ld e, $01
    ld bc, $1e1d
    ld bc, $0101
    ld bc, $0a09
    ld bc, $1901
    ld a, [de]
    ld sp, $0131
    ld bc, $3030
    ld bc, $0101
    ld bc, $3131
    ld bc, $3001
    jr nc, jr_01a_7a6a

    ld sp, $0101
    ld hl, $0131
    ld bc, $0e0d
    dec c
    ld c, $4c
    ld c, l
    ld c, h
    ld c, l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $5e01
    ld e, [hl]
    ld bc, $5e01
    ld e, [hl]
    add hl, bc
    ld a, [bc]

jr_01a_7a6a:
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld a, [hl+]
    ld l, $01
    ld bc, $3c3a
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    dec l
    ld a, [hl+]
    ld bc, $3b01
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $5242
    ld d, d
    ld b, d
    ld b, d
    ld d, d
    ld d, d
    ld b, d
    ld bc, $0101
    ld bc, $0101
    ld bc, $0801
    ld [$0808], sp
    jr jr_01a_7ac6

    jr @+$1a

    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    ld bc, $0101
    ld bc, $0101

jr_01a_7ac6:
    ld bc, $0101
    ld bc, $3121
    ld bc, $2001
    jr nc, jr_01a_7b03

    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld bc, $5301
    ld d, h
    ld bc, $3601
    ld h, $01
    ld bc, $5453
    ld bc, $3601
    ld h, $03
    inc b
    ld bc, $1301
    ld c, [hl]
    ld bc, $0301
    inc b
    ld bc, $1301
    ld c, [hl]
    ld bc, $0901
    ld a, [bc]
    add hl, bc

jr_01a_7b03:
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0d01
    ld [bc], a
    ld [bc], a
    ld c, $1d
    dec [hl]
    dec [hl]
    ld e, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec e
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $44
    ld b, l
    ld b, l
    ld b, h
    ld bc, $0101
    ld bc, $0101
    ld bc, $5301
    ld d, h
    ld bc, $3601
    ld h, $01
    ld bc, $5453
    ld bc, $3601
    ld h, $01
    ld bc, $0a09
    ld bc, $1901
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $4201
    ld d, d
    inc bc
    inc b
    ld b, d
    ld d, d
    inc de
    ld c, [hl]
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    dec l
    ld l, $57
    ld d, a
    dec hl
    inc l
    ld e, c
    ld e, c
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $5701
    ld d, a
    ld d, a
    ld d, a
    ld e, c
    ld e, c
    ld e, c
    ld e, c
    ld bc, $0101
    ld bc, $0101
    ld bc, $5701
    ld d, a
    dec l
    ld l, $59
    ld e, c
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    ld b, d
    ld d, d
    ld d, d
    ld d, d
    dec l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec hl
    inc l
    ld a, [hl-]
    ld a, [hl-]
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2a01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $2a01
    ld a, [hl+]
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    jr z, jr_01a_7c2b

    ld bc, $3801
    add hl, sp
    ld bc, $3801
    add hl, sp
    ld bc, $1901
    ld a, [de]
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $0101
    ld bc, $0101
    ld bc, $2701
    cpl
    ld bc, $3701

jr_01a_7c2b:
    ccf
    ld bc, $3d01
    ld a, $01
    ld bc, $2c2b
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    dec c
    ld [bc], a
    ld [bc], a
    ld c, $1d
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $44
    ld b, l
    ld b, l
    ld b, h
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2d01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec sp
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $2a01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    ld a, [hl-]
    inc a
    ld a, [hl+]
    ld a, [hl+]
    ld b, a
    ld e, a
    ld a, [hl-]
    ld a, [hl-]
    ld e, h
    ld e, l
    ld bc, $0101
    ld bc, $0101
    ld bc, $3201
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld sp, $0131
    ld bc, $3030
    ld bc, $0101
    ld bc, $3020
    ld bc, $2001
    jr nc, @+$03

    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    dec bc
    inc c
    ld bc, $1b01
    inc e
    ld b, b
    ld b, b
    dec hl
    inc l
    ld d, b
    ld d, b
    dec sp
    inc a
    ld de, $1111
    ld de, $1111
    ld de, $2b11
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld a, [hl+]
    ld a, [hl+]
    dec hl
    inc l
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld a, [hl+]
    ld a, [hl+]
    dec hl
    inc l
    ld a, [hl-]
    ld a, [hl-]
    dec hl
    inc l
    ld bc, $0101
    ld bc, $0101
    ld bc, $2d01
    ld l, $01
    ld bc, $2c2b
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    dec l
    ld l, $01
    ld bc, $2c2b
    ld [$0808], sp
    ld [$1818], sp
    jr @+$1a

    ld bc, $0101
    ld bc, $0101
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $3b01
    inc a
    ld bc, $0101
    ld bc, $2c2b
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $3b01
    inc a
    ld bc, $0101
    ld bc, $0101
    ld bc, $2d01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec sp
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $2a01
    ld a, [hl+]
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    ld a, [hl-]
    inc a
    dec l
    ld l, $01
    ld bc, $2c2b
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $0101
    ld bc, $2e2d
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    dec hl
    inc l
    ld d, e
    ld d, h
    dec hl
    inc l
    ld [hl], $26
    dec hl
    inc l
    ld d, e
    ld d, h
    dec hl
    inc l
    ld [hl], $26
    ld d, e
    ld d, h
    dec hl
    inc l
    ld [hl], $26
    dec hl
    inc l
    ld d, e
    ld d, h
    dec hl
    inc l
    ld [hl], $26
    dec hl
    inc l
    ld bc, $2701
    cpl
    ld bc, $3701
    ccf
    ld bc, $4a01
    ld c, e
    ld bc, $4c01
    ld c, l
    ld bc, $2401
    dec h
    ld bc, $2401
    dec h
    ld bc, $2401
    dec h
    ld bc, $2401
    dec h
    dec l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec hl
    inc l
    dec c
    ld c, $2b
    inc l
    dec c
    ld c, $2b
    inc l
    dec e
    ld e, $2a
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec c
    ld c, $0d
    ld c, $4a
    ld c, e
    ld c, d
    ld c, e
    ld c, h
    ld c, l
    ld c, h
    ld c, l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld l, $0d
    ld c, $2b
    inc l
    dec c
    ld c, $2b
    inc l
    dec e
    ld e, $2b
    inc l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    ld a, [hl-]
    inc a
    ld bc, $0101
    ld bc, $0101
    ld bc, $2b01
    inc l
    dec c
    ld c, $2b
    inc l
    dec e
    ld e, $2b
    inc l
    ld c, d
    ld c, e
    dec hl
    inc l
    ld c, h
    ld c, l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld d, e
    ld d, h
    ld d, e
    ld d, h
    ld [hl], $26
    ld [hl], $26
    dec c
    ld c, $2b
    inc l
    dec e
    ld e, $2b
    inc l
    ld c, d
    ld c, e
    dec hl
    inc l
    ld c, h
    ld c, l
    dec hl
    inc l
    dec l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec sp
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $2d01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec hl
    inc l
    ld a, [hl-]
    ld a, [hl-]
    dec hl
    inc l
    ld d, e
    ld d, h
    dec hl
    inc l
    ld [hl], $26
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    dec hl
    inc l
    ld d, e
    ld d, h
    dec hl
    inc l
    ld [hl], $26
    dec hl
    inc l
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    inc bc
    inc b
    ld bc, $1301
    ld c, [hl]
    ld bc, $2b01
    inc l
    ld a, [hl+]
    ld a, [hl+]
    dec hl
    inc l
    dec c
    ld c, $2b
    inc l
    ld c, d
    ld c, e
    dec hl
    inc l
    ld c, h
    ld c, l
    ld b, c
    ld de, $1111
    ld b, c
    ld de, $1111
    ld b, c
    ld de, $1111
    ld b, c
    ld de, $1111
    ld b, c
    ld de, $1111
    ld d, c
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0111
    ld bc, $0403
    ld bc, $1301
    ld c, [hl]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0c0b
    ld bc, $1b01
    inc e
    ld bc, $0101
    ld bc, $0101
    ld bc, $2b01
    inc l
    ld bc, $3b01
    inc a
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    dec hl
    inc l
    ld bc, $3b01
    inc a
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $2a2d
    ld a, [hl+]
    ld l, $3b
    ld a, [hl-]
    ld a, [hl-]
    inc a
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    dec bc
    inc c
    ld bc, $1b01
    inc e
    ld bc, $2d01
    ld l, $01
    ld bc, $2c2b
    ld bc, $2b01
    inc l
    ld bc, $3b01
    inc a
    ld bc, $4f01
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    inc d
    inc d
    inc d
    ld c, a
    inc d
    inc d
    inc d
    ld c, a
    inc d
    inc d
    inc d
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    inc d
    inc d
    inc d
    ld c, a
    inc d
    inc d
    inc d
    ld c, a
    inc d
    inc d
    inc d
    ld c, a
    ld bc, $0101
    ld bc, $2f27
    ld bc, $3701
    ccf
    ld bc, $3d01
    ld a, $01
    ld bc, $4623
    ld bc, $4801
    ld c, c
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $2c2b
    add hl, bc
    ld a, [bc]
    dec hl
    inc l
    add hl, de
    ld a, [de]
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2a01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0d01
    ld [bc], a
    ld [bc], a
    ld c, $1d
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $1d
    dec [hl]
    dec [hl]
    ld e, $56
    ld d, [hl]
    ld d, a
    ld d, a
    ld e, b
    ld e, b
    ld e, c
    ld e, c
    ld bc, $0101
    ld bc, $0101
    ld bc, $5a01
    ld e, e
    ld d, a
    ld d, a
    ld b, e
    inc [hl]
    ld e, c
    ld e, c
    ld bc, $0101
    ld bc, $0101
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld [bc], a
    ld [bc], a
    dec hl
    inc l
    ld [de], a
    ld [de], a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec c
    ld c, $59
    ld e, c
    dec e
    ld e, $01
    ld bc, $1e1d
    ld bc, $1a01
    cp $a5
    ret z

    ld hl, $d03f
    ld a, [hl+]
    and $07
    ret nz

    bit 6, [hl]
    ret nz

    ld hl, $d014
    call Call_01a_7ff6
    ld a, [$d041]
    bit 3, a
    ret nz

    ld hl, $d148
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1

Call_01a_7ff6:
    ld a, [$cc2e]
    ld c, a
    ld b, $00
    add hl, bc
    dec [hl]
    ret


    nop
