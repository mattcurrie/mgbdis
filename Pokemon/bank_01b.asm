; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $01b", ROMX[$4000], BANK[$1b]

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0200
    nop
    inc b
    nop
    ld [$1800], sp
    nop
    inc h
    nop
    ld b, d
    nop
    add c
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
    nop
    rst $38
    nop
    rst $38
    nop
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
    nop
    nop
    rrca
    rrca
    dec d
    db $10
    ld a, [de]
    db $10
    db $10
    rra
    rla
    jr jr_01b_4071

    dec de
    ld [hl], a
    ld a, b
    nop
    nop
    ldh a, [$f0]
    ld e, b
    ld [$08a8], sp
    ld [$e8f8], sp
    jr jr_01b_4095

    ret c

    xor $1e

Jump_01b_4070:
    rst $38

jr_01b_4071:
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
    rst $38
    rst $38
    add b
    ret nz

jr_01b_4095:
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
    nop
    rst $38
    nop
    rst $38
    rst $38
    ld e, d
    and b
    and l
    ld d, b
    ld e, d
    and b
    and l
    ld d, b
    and l
    ld a, [bc]
    ld e, d
    dec b
    and l
    ld a, [bc]
    ld e, d
    dec b
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
    ld d, l
    ld e, d
    ld [hl], a
    ld e, b
    ld d, b
    ld e, a
    ld a, a
    ld e, a
    ld a, a
    ld b, b
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ld a, a
    ld a, a
    ld a, [hl+]
    jp c, Jump_000_1aee

    ld a, [bc]
    ld a, [$fafe]
    cp $02
    ld [bc], a
    cp $02
    cp $fe
    cp $aa
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
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38

jr_01b_4208:
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    cp a
    add b
    cp a
    add b
    add b
    rst $38
    rst $38
    rst $38
    sub b
    ldh a, [$90]
    ldh a, [$90]
    ldh a, [rP1]
    nop
    nop
    ld a, [hl]
    nop
    ld b, d
    nop
    ld b, d
    nop
    ld b, d
    nop
    ld b, d
    nop
    ld a, [hl]
    nop
    nop
    rst $38
    rst $38
    db $fd
    inc bc
    db $fd
    inc bc
    ld bc, $ffff
    rst $38
    add hl, bc
    rrca
    add hl, bc
    rrca
    add hl, bc
    rrca
    rlca
    rlca
    rlca
    inc b
    rlca
    inc b
    rlca
    inc b
    rlca
    inc b
    rlca
    inc b
    rlca
    inc b
    rlca
    inc b
    rst $38
    ldh [rIE], a
    jr nz, @+$01

    jr nz, @+$01

    jr nz, @+$01

    jr nz, @+$01

    jr nz, @+$01

    jr nz, @+$01

    jr nz, jr_01b_4208

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

jr_01b_42f2:
    ld l, h
    ld l, h
    ld d, [hl]
    ld a, d
    adc h
    db $f4
    jr z, jr_01b_42f2

    ld b, h
    call c, $fe06
    cp c
    ld a, c
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
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    sub b
    ldh a, [$90]
    ldh a, [$90]
    ldh a, [$90]
    ldh a, [$9f]
    rst $38
    rst $38
    rst $38
    adc h
    ei
    rst $38
    rst $38
    xor d
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
    add hl, bc
    rrca
    add hl, bc
    rrca
    add hl, bc
    rrca
    add hl, bc
    rrca
    ld sp, hl
    rst $38
    rst $38
    rst $38
    ld sp, $ffdf
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
    add b
    rst $38
    ld a, a
    ld a, a
    ld b, h
    ld a, a
    ld e, a
    ld b, a
    ld e, a
    ld b, h
    ld a, a
    ld a, h
    nop
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
    rst $38
    nop
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
    ld bc, $feff
    cp $22
    cp $fe
    ld [c], a
    cp $22
    cp $3e
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
    rst $38
    rst $38
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
    add b
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    db $fd
    ld bc, $01fd
    rst $38
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $ffff
    rst $38
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
    call c, $abd5
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

jr_01b_451a:
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
    jr jr_01b_451a

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
    ld bc, $0200
    nop
    inc b
    nop
    ld [$1800], sp
    nop
    inc [hl]
    ld [$5cbf], sp
    db $e3
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
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0a09
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
    ld de, $1111
    ld de, $1111
    ld de, $0911
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
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld de, $1111
    ld de, $1111
    ld de, $0911
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
    ld de, $1911
    ld a, [de]
    ld de, $0911
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld de, $0911
    ld a, [bc]
    ld de, $1911
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
    add hl, bc
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    ld de, $1111
    ld de, $0a09
    ld de, $1911
    ld a, [de]
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    add hl, bc
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    ld de, $0111
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    db $10
    db $10
    db $10
    db $10
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld de, $0911
    ld a, [bc]
    ld de, $1911
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
    dec bc
    inc c
    add hl, de
    ld a, [de]
    dec de
    inc e
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    inc bc
    inc b
    add hl, bc
    ld a, [bc]
    inc de
    inc d
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0605
    ld bc, $1501
    ld d, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    inc bc
    inc b
    add hl, de
    ld a, [de]
    inc de
    inc d
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    dec bc
    inc c
    add hl, bc
    ld a, [bc]
    dec de
    inc e
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0501
    ld b, $01
    ld bc, $1615
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    add hl, bc
    ld a, [bc]
    db $10
    db $10
    add hl, de
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    db $10
    db $10
    db $10
    db $10
    ld bc, $0101
    ld bc, $0a09
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    db $10
    db $10
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0301
    inc b
    ld bc, $1301
    inc d
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
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
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
    ld bc, $0201
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    db $10
    db $10
    db $10
    db $10
    ld bc, $0101
    ld bc, $0202
    dec c
    ld c, $12
    ld [de], a
    dec e
    ld e, $10
    db $10
    dec e
    ld e, $01
    ld bc, $1e1d
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    db $10
    db $10
    db $10
    db $10
    ld bc, $0101
    ld bc, $0101
    dec e
    ld e, $01
    ld bc, $1e1d
    ld bc, $1d01
    ld e, $01
    ld bc, $1e1d
    ld bc, $0101
    ld bc, $0101
    ld bc, $0f01
    rrca
    rrca
    rrca
    rra
    rra
    rra
    rra
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0901
    ld a, [bc]
    rrca
    rrca
    add hl, de
    ld a, [de]
    rra
    rra
    ld bc, $0901
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    rrca
    rrca
    add hl, bc
    ld a, [bc]
    rra
    rra
    add hl, de
    ld a, [de]
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld bc, $1d01
    ld e, $01
    ld bc, $1e1d
    rrca
    rrca
    rrca
    rrca
    rra
    rra
    rra
    rra
    dec c
    ld [bc], a
    ld [bc], a
    ld c, $21
    jr nz, jr_01b_48a7

    inc hl
    ld sp, $3030
    inc sp
    dec a
    ld a, $3d
    ld a, $01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0807
    rlca
    ld [$1817], sp
    rla
    jr jr_01b_48aa

    ld a, [bc]
    rra
    rra
    add hl, de
    ld a, [de]
    rra

jr_01b_48a7:
    rra
    add hl, bc
    ld a, [bc]

jr_01b_48aa:
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    rra
    rra
    add hl, bc
    ld a, [bc]
    rra
    rra
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
    add hl, bc
    ld a, [bc]
    inc bc
    inc b
    add hl, de
    ld a, [de]
    inc de
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
    dec bc
    inc c
    add hl, de
    ld a, [de]
    dec de
    inc e
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    inc bc
    inc b
    ld bc, $1301
    inc d
    ld bc, $0301
    inc b
    ld bc, $1301
    inc d
    ld bc, $2201
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    db $10
    db $10
    db $10
    db $10
    ld bc, $0101
    ld bc, $0a09
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
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    add hl, bc
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
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
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
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0701
    ld [$0807], sp
    rla
    jr @+$19

    jr @+$03

    ld bc, $0101
    ld bc, $0101
    ld bc, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    ld de, $1111
    ld de, $1111
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    ld de, $0911
    ld a, [bc]
    ld de, $1911
    ld a, [de]
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $0202
    ld [bc], a
    ld [bc], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
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
    db $10
    db $10
    dec hl
    inc l
    ld bc, $2a01
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    db $10
    db $10
    db $10
    db $10
    ld bc, $0101
    ld bc, $2a2a
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    dec hl
    inc l
    db $10
    db $10
    dec hl
    inc l
    ld bc, $2b01
    inc l
    jr z, @+$2b

    jr z, jr_01b_4a1d

    jr c, jr_01b_4a2f

    jr c, @+$3b

    jr c, @+$3b

    jr c, @+$3b

    ld c, b
    ld c, c
    ld c, b
    ld c, c
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $0101
    ld bc, $0101
    daa
    cpl
    ld bc, $3701
    ccf
    ld bc, $3d01

jr_01b_4a1d:
    ld a, $01
    ld bc, $0101
    dec hl
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01
    inc l
    ld bc, $2b01

jr_01b_4a2f:
    inc l
    jr nz, @+$22

    jr nz, @+$22

    jr nc, @+$32

    jr nc, jr_01b_4a68

    ld bc, $0101
    ld bc, $0101
    ld bc, $2b01
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

jr_01b_4a68:
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld l, $3a
    ld a, [hl-]
    ld a, [hl-]
    inc a
    ld bc, $0101
    ld bc, $0101
    daa
    cpl
    ld bc, $3701
    ccf
    ld bc, $3d01
    ld a, $05
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0605
    ld bc, $1501
    ld d, $01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0501
    ld b, $01
    ld bc, $1615
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0605
    dec b
    ld b, $15
    ld d, $15
    ld d, $01
    ld bc, $0605
    ld bc, $1501
    ld d, $01
    ld bc, $0605
    ld bc, $1501
    ld d, $05
    ld b, $01
    ld bc, $1615
    ld bc, $0501
    ld b, $01
    ld bc, $1615
    ld bc, $0501
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $05
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $09
    ld a, [bc]
    dec b
    ld b, $19
    ld a, [de]
    dec d
    ld d, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $09
    ld a, [bc]
    dec d
    ld d, $19
    ld a, [de]
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $01
    ld bc, $1615
    ld bc, $0901
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $09
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
    dec b
    ld b, $19
    ld a, [de]
    dec d
    ld d, $01
    ld bc, $0a09
    ld bc, $1901
    ld a, [de]
    dec b
    ld b, $09
    ld a, [bc]
    dec d
    ld d, $19
    ld a, [de]
    dec b
    ld b, $09
    ld a, [bc]
    dec d
    ld d, $19
    ld a, [de]
    dec b
    ld b, $09
    ld a, [bc]
    dec d
    ld d, $19
    ld a, [de]
    add hl, bc
    ld a, [bc]
    dec b
    ld b, $19
    ld a, [de]
    dec d
    ld d, $09
    ld a, [bc]
    dec b
    ld b, $19
    ld a, [de]
    dec d
    ld d, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    ld bc, $0501
    ld b, $01
    ld bc, $1615
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $01
    ld bc, $1615
    ld bc, $0901
    ld a, [bc]
    dec b
    ld b, $19
    ld a, [de]
    dec d
    ld d, $09
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    ld bc, $0501
    ld b, $09
    ld a, [bc]
    dec d
    ld d, $19
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
    dec b
    ld b, $19
    ld a, [de]
    dec d
    ld d, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $09
    ld a, [bc]
    dec d
    ld d, $19
    ld a, [de]
    ld bc, $0501
    ld b, $01
    ld bc, $1615
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
    ld bc, $0501
    ld b, $01
    ld bc, $1615
    add hl, bc
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    dec b
    ld b, $01
    ld bc, $1615
    ld bc, $0101
    ld bc, $0605
    ld bc, $1501
    ld d, $05
    ld b, $01
    ld bc, $1615
    ld bc, $0501
    ld b, $01
    ld bc, $1615
    ld bc, $0101
    ld bc, $0605
    ld bc, $1501
    ld d, $05
    ld b, $01
    ld bc, $1615
    ld bc, $0501
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $01
    ld bc, $0605
    ld bc, $1501
    ld d, $05
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $05
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $05
    ld b, $01
    ld bc, $1615
    ld bc, $0501
    ld b, $05
    ld b, $15
    ld d, $15
    ld d, $01
    ld bc, $0605
    ld bc, $1501
    ld d, $09
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    add hl, de
    ld a, [de]
    add hl, de
    ld a, [de]
    db $10
    db $10
    dec b
    ld b, $01
    ld bc, $1615
    add hl, bc
    ld a, [bc]
    ld bc, $1901
    ld a, [de]
    daa
    cpl
    add hl, bc
    ld a, [bc]
    scf
    ccf
    add hl, de
    ld a, [de]
    dec a
    ld a, $01
    ld bc, $0a09
    daa
    cpl
    add hl, de
    ld a, [de]
    scf
    ccf
    add hl, bc
    ld a, [bc]
    dec a
    ld a, $19
    ld a, [de]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, h
    ld bc, $01ab
    ld d, h
    ld bc, $01ab
    ld a, e
    ld bc, $01a0
    pop de
    ld bc, $ff54
    rlca
    rst $38
    add hl, de
    ld hl, sp+$7e
    ldh [$a9], a
    and h
    ld e, d
    ld b, b
    db $ed
    add b
    rst $10
    adc b
    rst $28
    add b
    ldh [rIE], a
    ld d, h
    rra
    cp a
    ld c, $6f
    dec d
    rst $38
    ld a, [bc]
    db $fd
    rlca
    xor a
    ld e, e
    ld e, l
    and a
    nop
    rst $38
    inc bc
    rst $38
    inc e
    db $fc
    inc hl
    db $e4
    ld [hl+], a
    db $e4
    ld c, h
    ret


    ld c, c
    ret nc

    push hl
    xor c
    cp $00
    rst $30
    nop
    rst $28
    nop
    rst $30
    nop
    cp d
    ld b, l
    rst $30
    ld [$00af], sp
    sub $01
    xor d
    rst $38
    ld a, [hl+]
    add b
    push de
    add b
    ld a, [hl+]
    add b
    ld a, [$2180]
    add b
    ld d, b
    add b
    dec hl
    add b
    add b
    rst $38
    ret nz

    rst $38
    ld hl, sp+$3f
    inc a
    rst $20

jr_01b_4d18:
    cp h
    ld h, a
    sbc $b3
    ld l, [hl]
    sbc e

jr_01b_4d1e:
    db $dd
    or a
    inc d
    db $eb
    inc a
    rst $18
    ld d, a
    or a
    scf
    rst $10
    jr nc, jr_01b_4d1e

    scf
    rst $30
    ld [hl], a
    rst $30
    ld [hl], b
    db $f4
    inc b
    ei
    jr c, @+$01

    add sp, -$11
    add sp, -$11
    inc c
    cpl
    db $ec
    rst $28
    xor $ef
    ld c, $2f
    rra
    rst $38
    jr nc, jr_01b_4d18

    ld d, a
    or a
    scf
    rst $10
    db $10
    db $f4
    rla
    rst $30
    rla
    rst $30
    db $10
    db $f4
    db $fc
    ei
    ld [$e82f], sp
    rst $28
    add sp, -$11
    ld [$e82f], sp
    rst $28
    add sp, -$11
    ld [$1c2f], sp
    ei
    ld h, l
    rst $20
    ld a, a
    jp $da7e


    and $e6
    ld hl, $41e1
    ret nz

    ld b, c
    ret nz

    ld [hl], h
    db $eb
    sbc c
    sbc a
    and h
    xor a
    ld d, h
    ld c, a
    dec d
    rrca
    xor d
    adc a
    ld a, l
    ld a, a
    ld b, h
    ld b, a
    dec d
    db $eb
    ld l, e
    sub $7f
    rst $38
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
    sub h
    db $eb
    jp hl


    ld d, a
    cp $ff
    ld bc, $01ff
    ld bc, $99ff
    di
    db $d3
    ld bc, $6201
    ld a, [hl]
    sbc h
    ld a, h
    and h
    ld h, h
    ld b, e
    ld [c], a
    ld [hl], d
    jp $c7b9


    ld sp, hl
    rst $00
    xor e
    rst $38
    ld h, e
    ld a, a
    sbc a
    ld a, a
    and e
    ld h, e
    ld b, c
    pop hl
    ld [hl], c
    jp $c7ba


    cp $c7
    xor h
    rst $38
    rst $18
    add b
    ei
    db $e4
    pop af
    call nc, $8dda
    db $e4
    sbc d
    ld a, [$78b5]
    rst $28
    ccf
    rst $10
    xor a
    ld e, e
    push af
    rrca
    cp e
    cpl
    ld e, l
    or a
    dec hl
    ld e, a
    ld e, l
    xor a
    ld e, $f7
    db $fc
    db $eb
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
    call c, $f08f
    adc a
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
    or e
    rst $38
    ld sp, hl
    rst $38
    cp $27
    cp $23
    ld [hl], a
    sbc c
    dec a
    rst $18
    ld e, [hl]
    di
    cp a
    db $e3
    ld a, a
    rst $30
    ld a, a
    rst $30
    ld [hl], b
    cp a
    scf
    rst $38
    rra
    rst $38
    rlca
    rst $38
    nop
    rst $38
    nop
    rst $38
    cp $ef
    cp $ef
    inc c
    rst $38
    db $ec
    rst $38
    ld hl, sp-$01
    ldh [rIE], a
    nop
    rst $38
    nop
    rst $38
    rra
    rst $30
    ccf
    rst $10
    ld d, e
    cp h
    scf
    rst $18
    inc e
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    db $fc
    db $eb
    ld hl, sp-$11
    ret z

    ccf
    add sp, -$01
    jr c, @+$01

    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    add d
    ldh a, [$80]
    db $fc
    xor e
    rst $38
    ld [hl], l
    rst $38
    sbc e
    rst $38
    rrca
    cp $05
    rst $38
    ld b, b
    rst $38
    and [hl]
    add a
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
    rst $38
    ld a, b
    rst $38
    ld b, b
    ret nz

    rst $38
    sub l
    add b
    add b
    ld a, a

jr_01b_4e87:
    rst $38
    add [hl]
    rst $38
    rrca
    cp $07
    rst $38
    ld b, e
    rst $38
    ld bc, $ff01
    ld d, c
    ld bc, $fe01
    rst $38
    ld b, l
    rst $38
    ld [$e57f], a
    rst $38
    ret nz

    rst $38
    inc d
    db $eb
    ld l, c
    rst $10
    ld d, b
    xor a
    jr nz, jr_01b_4e87

    add l
    rst $38
    ld a, [bc]
    rst $38
    dec b
    rst $38
    ld b, b
    rst $38
    xor d
    ld d, l
    dec b
    xor d
    ld [$5155], sp
    xor d
    ld [$0155], sp
    xor d
    ld [$5555], sp
    xor d
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
    inc c
    rst $38
    ld a, [hl+]
    db $e3
    ld d, l
    jp $c56b


    and [hl]
    ei
    dec e
    rst $38
    dec b
    rst $38
    ld b, b
    rst $38
    push de
    add b
    ld a, [hl+]
    add b
    push de
    add b
    ld a, [hl+]
    add b
    ld a, [$2180]
    add b
    ld d, b
    add b
    ld d, h
    rst $38
    or d
    call $9f69
    and b
    ld h, h
    call nz, Call_000_1944
    adc b
    ld d, e
    cp b
    call $824a
    push bc
    push de
    xor e
    ld b, l
    ld e, [hl]
    sbc d
    ld a, $5f
    cp b
    ld a, $54
    ld l, l
    and b
    ld [hl-], a
    ld [c], a
    jp hl


    add c
    xor b
    rst $38
    xor e
    ld bc, $0154
    xor e
    ld bc, $017b
    and b
    ld bc, $01d1
    xor d
    ld bc, $827e
    sbc h
    db $fc
    ld [hl+], a
    ld [c], a
    pop bc
    ld h, c
    ldh a, [rSCX]
    ld hl, sp-$39
    ld a, c
    rst $20
    dec de
    rst $38
    ld l, d
    rst $38
    xor e
    add c
    push de
    nop
    cp [hl]
    nop
    cp d
    ld b, l
    rst $30
    ld [$00ff], sp
    ld [hl], a
    adc b
    ld b, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    and d
    rst $38
    dec d
    rst $38
    xor d

jr_01b_4f4b:
    rst $38
    ld d, l
    rst $38
    xor b
    rst $38
    inc d
    db $eb
    ld l, c
    rst $10
    ld d, e
    xor a
    inc l
    call c, $f390
    inc de
    db $f4
    ld h, $e8
    ld h, [hl]
    add sp, $14
    db $eb
    ld l, c
    rst $10
    ret nc

    rst $28
    jr nc, jr_01b_4fa7

    dec c
    rst $08
    jp z, Jump_01b_652f

    rla
    ld h, h
    rla
    daa
    add sp, $67
    add sp, $53
    or h
    jr nc, jr_01b_4f4b

    adc h
    db $fc
    dec bc
    rst $38
    dec b
    rst $38
    ld b, b
    rst $38
    db $e4
    rla
    push hl
    rla
    ret z

    cpl
    ld [$35cf], sp
    ccf
    jp z, Jump_000_05ff

    rst $38
    ld b, b
    rst $38
    inc d
    db $eb
    db $eb
    rst $10
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
    ld l, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38

jr_01b_4fa7:
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    or d
    call $9f69
    and b
    db $e4
    ld b, h
    call nz, $8899
    inc de
    cp b
    call $02ca
    push bc
    nop
    rst $38
    inc bc
    rst $38
    ld c, $fe
    dec de
    db $fc
    ld [hl-], a
    db $f4
    ld l, h
    pop hl
    ld e, c
    jp nz, $81ec

    rst $38
    rst $38
    rst $10
    nop
    nop
    xor a
    nop
    ld e, a
    inc d
    xor d
    jr z, jr_01b_5030

    ld d, b
    xor b
    and b
    ld d, c
    add b
    rst $38
    ld b, b
    rst $38
    jr nc, @+$01

    jr @+$01

    inc e
    rst $28
    inc b
    rst $38
    ld d, $eb
    add hl, hl
    rst $10
    push de
    add c
    sbc b
    ld [c], a
    and c
    call nc, $cd52
    inc h
    ld a, [$f418]
    ld [$07f8], sp
    rst $38
    push de
    xor e
    ld d, h
    ld b, [hl]
    and b
    dec c
    ld b, l
    ld [de], a
    and b
    rrca
    ld b, b
    rla
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    xor e
    ld d, l
    ld e, a
    cp e
    cpl
    ld e, [hl]
    or a
    inc l
    ld e, a
    ld e, b
    xor a
    db $10
    rst $38
    ldh [rIE], a
    db $eb
    nop
    rst $10
    nop
    xor a
    nop
    ld e, a
    nop
    cp [hl]
    nop
    ld a, h
    nop
    ld hl, sp+$00
    pop af
    nop

jr_01b_5030:
    or h
    pop bc
    cp e
    ret nz

    ld d, h
    ld h, b
    add b

jr_01b_5037:
    and b
    ld d, b
    ld b, b
    db $ed
    add b
    ret nc

    add b
    jp hl


    add b
    ld de, $01af
    rst $18
    ld de, $0bee
    push af
    dec d
    ld [$f709], a
    dec d
    db $eb
    add hl, hl
    rst $10
    inc d
    db $eb
    nop
    rst $38
    ld d, b
    xor a
    jr nz, jr_01b_5037

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
    rlca
    rst $38
    rra
    ld hl, sp+$3f
    ldh [$7b], a
    call nz, $c07f
    rst $38
    add b
    rst $30
    adc b
    cp a
    ret nz

    ldh [rIE], a
    ld hl, sp+$1f
    db $fc
    rlca
    xor $17
    cp $0b
    db $fd
    rlca
    xor a
    ld e, e
    ld e, l
    and a
    rst $38
    add b
    or l
    ld [$e5fa], a
    ldh a, [$cf]
    add sp, -$41
    push de
    rst $38
    ld l, e
    rst $38
    rra
    rst $38
    xor a
    ld e, e
    ld d, l
    xor a
    cp e
    ld l, a
    ld e, a
    or a
    dec bc
    rst $38
    ld d, l
    rst $38
    xor [hl]
    rst $38
    ld hl, sp-$01
    cp $00
    rst $30
    nop
    rst $28
    nop
    rst $30
    nop
    cp d
    ld b, l
    rst $30
    ld [$00af], sp
    sub $01
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr nz, jr_01b_50f2

    jr nz, jr_01b_50f4

    jr nz, jr_01b_50f6

    jr nz, jr_01b_50f8

    jr nz, jr_01b_50fa

    jr nz, jr_01b_50fc

    jr nz, jr_01b_50fe

    jr nz, jr_01b_5100

    inc b
    add hl, hl
    add hl, hl
    rlca
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    jr z, jr_01b_50fe

    db $10
    ld de, $3c3c

jr_01b_50f2:
    inc a
    inc a

jr_01b_50f4:
    inc a
    inc a

jr_01b_50f6:
    inc a
    inc a

jr_01b_50f8:
    inc a
    inc a

jr_01b_50fa:
    inc a
    inc a

jr_01b_50fc:
    inc a
    inc a

jr_01b_50fe:
    inc a
    inc a

jr_01b_5100:
    jr nz, jr_01b_5122

    jr nz, jr_01b_5124

    jr nz, jr_01b_5126

    jr nz, jr_01b_5128

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
    jr nz, jr_01b_513a

    jr nz, jr_01b_513c

    jr nz, jr_01b_513e

    jr nz, jr_01b_5140

    ld [bc], a
    inc bc

jr_01b_5122:
    jr nz, jr_01b_5144

jr_01b_5124:
    ld [de], a
    inc de

jr_01b_5126:
    jr nz, jr_01b_5148

jr_01b_5128:
    ld [bc], a
    inc bc
    jr nz, jr_01b_514c

    ld [de], a
    inc de
    jr nz, jr_01b_5150

    jr nz, jr_01b_5152

    ld [bc], a
    inc bc
    jr nz, jr_01b_5156

    ld [de], a
    inc de
    jr nz, jr_01b_515a

jr_01b_513a:
    ld [bc], a
    inc bc

jr_01b_513c:
    jr nz, jr_01b_515e

jr_01b_513e:
    ld [de], a
    inc de

jr_01b_5140:
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01b_5144:
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01b_5148:
    ld [bc], a
    inc bc
    jr nz, jr_01b_516c

jr_01b_514c:
    ld [de], a
    inc de
    jr nz, jr_01b_5170

jr_01b_5150:
    ld [bc], a
    inc bc

jr_01b_5152:
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01b_5156:
    ld [de], a
    inc de
    jr nz, jr_01b_517a

jr_01b_515a:
    ld [bc], a
    inc bc
    jr nz, jr_01b_517e

jr_01b_515e:
    ld [de], a
    inc de
    ld [bc], a
    inc bc
    jr nz, jr_01b_5184

    ld [de], a
    inc de
    jr nz, jr_01b_5188

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01b_516c:
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01b_5170:
    jr nz, jr_01b_5192

    ld [bc], a
    inc bc
    jr nz, jr_01b_5196

    ld [de], a
    inc de
    ld [bc], a
    inc bc

jr_01b_517a:
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01b_517e:
    ld [de], a
    inc de
    jr nz, jr_01b_51a2

    jr nz, jr_01b_51a4

jr_01b_5184:
    jr nz, jr_01b_51a6

    jr nz, jr_01b_51a8

jr_01b_5188:
    ld [bc], a
    inc bc
    jr nz, jr_01b_51ac

    ld [de], a
    inc de
    jr nz, jr_01b_51b0

    jr nz, jr_01b_51b2

jr_01b_5192:
    jr nz, jr_01b_51b4

    jr nz, jr_01b_51b6

jr_01b_5196:
    jr nz, jr_01b_51b8

    jr nz, jr_01b_51ba

    ld [bc], a
    inc bc
    jr nz, jr_01b_51be

    ld [de], a
    inc de
    ld [bc], a
    inc bc

jr_01b_51a2:
    jr nz, jr_01b_51c4

jr_01b_51a4:
    ld [de], a
    inc de

jr_01b_51a6:
    jr nz, jr_01b_51c8

jr_01b_51a8:
    jr nz, jr_01b_51ca

    jr nz, jr_01b_51cc

jr_01b_51ac:
    jr nz, jr_01b_51ce

    jr nz, jr_01b_51d0

jr_01b_51b0:
    jr nz, jr_01b_51d2

jr_01b_51b2:
    ld [bc], a
    inc bc

jr_01b_51b4:
    jr nz, jr_01b_51d6

jr_01b_51b6:
    ld [de], a
    inc de

jr_01b_51b8:
    jr nz, jr_01b_51da

jr_01b_51ba:
    jr nz, jr_01b_51dc

    jr nz, jr_01b_51de

jr_01b_51be:
    jr nz, jr_01b_51e0

    jr nz, jr_01b_51e2

    jr nz, jr_01b_51e4

jr_01b_51c4:
    jr nz, jr_01b_51e6

    jr nz, jr_01b_51e8

jr_01b_51c8:
    jr nz, jr_01b_51ea

jr_01b_51ca:
    ld [bc], a
    inc bc

jr_01b_51cc:
    jr nz, jr_01b_51ee

jr_01b_51ce:
    ld [de], a
    inc de

jr_01b_51d0:
    jr nz, jr_01b_51f2

jr_01b_51d2:
    jr nz, jr_01b_51f4

    jr nz, jr_01b_51f6

jr_01b_51d6:
    jr nz, jr_01b_51f8

    ld [bc], a
    inc bc

jr_01b_51da:
    jr nz, jr_01b_51fc

jr_01b_51dc:
    ld [de], a
    inc de

jr_01b_51de:
    jr nz, jr_01b_5200

jr_01b_51e0:
    jr nz, jr_01b_5202

jr_01b_51e2:
    ld [bc], a
    inc bc

jr_01b_51e4:
    jr nz, @+$22

jr_01b_51e6:
    ld [de], a
    inc de

jr_01b_51e8:
    jr nz, @+$22

jr_01b_51ea:
    jr nz, jr_01b_520c

    jr nz, @+$22

jr_01b_51ee:
    jr nz, jr_01b_5210

    ld [bc], a
    inc bc

jr_01b_51f2:
    jr nz, jr_01b_5214

jr_01b_51f4:
    ld [de], a
    inc de

jr_01b_51f6:
    jr nz, jr_01b_5218

jr_01b_51f8:
    jr nz, jr_01b_521a

    jr nz, jr_01b_521c

jr_01b_51fc:
    jr nz, jr_01b_521e

    jr nz, jr_01b_5220

jr_01b_5200:
    jr nz, @+$06

jr_01b_5202:
    add hl, hl
    add hl, hl
    inc b
    ld sp, $0505
    ld sp, $0531
    dec b

jr_01b_520c:
    ld sp, $0531
    dec b

jr_01b_5210:
    add hl, hl
    add hl, hl
    add hl, hl
    add hl, hl

jr_01b_5214:
    dec b
    dec b
    dec b
    dec b

jr_01b_5218:
    dec b
    dec b

jr_01b_521a:
    dec b
    dec b

jr_01b_521c:
    dec b
    dec b

jr_01b_521e:
    dec b
    dec b

jr_01b_5220:
    add hl, hl
    add hl, hl
    rlca
    jr nz, jr_01b_522a

    dec b
    rla
    rlca
    dec b
    dec b

jr_01b_522a:
    rla
    rla
    dec b
    dec b
    rla
    rla
    inc b
    add hl, hl
    add hl, hl
    rlca
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    rla
    rla
    dec b
    dec b
    rla
    rla
    dec b
    dec b
    rla
    rla
    dec b
    dec b
    rla
    rla
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    ld sp, $1028
    db $10
    jr z, jr_01b_529e

    db $10
    db $10
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10

jr_01b_529e:
    db $10
    db $10
    dec b
    dec b
    rla
    rla
    dec b
    dec b
    rla
    rla
    db $10
    db $10
    ld de, $1017
    db $10
    db $10
    ld de, $0531
    dec b
    rla
    ld sp, $0505
    rla
    ld sp, $0505
    rla
    jr z, jr_01b_52ce

    db $10
    ld de, $2904
    add hl, hl
    add hl, hl
    ld sp, $0505
    dec b
    ld sp, $0505
    dec b
    jr z, jr_01b_52de

jr_01b_52ce:
    db $10
    db $10
    add hl, hl
    add hl, hl
    add hl, hl
    add hl, hl
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10

jr_01b_52de:
    db $10
    db $10
    add hl, hl
    add hl, hl
    add hl, hl
    rlca
    dec b
    dec b
    dec b
    rla
    dec b
    dec b
    dec b
    rla
    db $10
    db $10
    db $10
    ld de, $0908

Jump_01b_52f2:
    ld [bc], a
    inc bc
    jr @+$1b

    ld [de], a
    inc de
    jr nz, jr_01b_531a

    jr nz, jr_01b_531c

    jr nz, jr_01b_531e

    jr nz, jr_01b_5320

    jr nz, jr_01b_5322

    jr nz, jr_01b_5324

    jr nz, jr_01b_5326

    jr nz, jr_01b_5328

    ld hl, $2121
    ld hl, $2121
    ld hl, $0521
    dec b
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $1010

jr_01b_531a:
    db $10
    db $10

jr_01b_531c:
    db $10
    db $10

jr_01b_531e:
    db $10
    db $10

jr_01b_5320:
    ld [bc], a
    inc bc

jr_01b_5322:
    add hl, hl
    add hl, hl

jr_01b_5324:
    ld [de], a
    inc de

jr_01b_5326:
    dec b
    dec b

jr_01b_5328:
    ld [bc], a
    inc bc
    dec b
    dec b
    ld [de], a
    inc de
    dec b
    dec b
    ld [$2009], sp
    jr nz, jr_01b_534d

    add hl, de
    jr nz, jr_01b_5358

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    ld [$2009], sp

jr_01b_534d:
    jr nz, jr_01b_5367

    add hl, de
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b

jr_01b_5358:
    dec d
    ld d, $15
    ld d, $15
    ld d, $15
    ld d, $20
    jr nz, jr_01b_5383

    jr nz, jr_01b_5385

    jr nz, jr_01b_5387

jr_01b_5367:
    jr nz, jr_01b_5389

    jr nz, jr_01b_5379

    rrca
    jr nz, jr_01b_538e

    ld e, $1f
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    db $10

jr_01b_5379:
    ld h, $05
    dec b
    ld h, $31
    dec b
    dec b
    dec b
    dec b
    dec b

jr_01b_5383:
    dec b
    dec b

jr_01b_5385:
    dec b
    dec b

jr_01b_5387:
    dec b
    dec b

jr_01b_5389:
    dec b
    dec h
    db $10
    dec b
    dec b

jr_01b_538e:
    rla
    dec h
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    dec d
    ld d, $10
    db $10
    dec d
    ld d, $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    ld b, $27
    ld b, $27
    inc h
    ld bc, $0124
    ld b, $27
    ld b, $27
    inc h
    ld bc, $0124
    dec b
    dec b
    dec h
    db $10
    dec b
    dec b
    rla
    dec h
    dec b
    dec b
    rla
    rla
    dec b
    dec b
    rla
    rla
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    jr nz, jr_01b_53fa

    jr nz, jr_01b_53fc

    jr nz, @+$22

    jr nz, jr_01b_5400

    db $10
    ld h, $05
    dec b
    ld h, $31
    dec b
    dec b
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    ld b, $27

jr_01b_53fa:
    ld b, $27

jr_01b_53fc:
    inc h
    ld bc, $0124

jr_01b_5400:
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $0505
    ld b, $27
    ld b, $27
    inc h
    ld bc, $0124
    dec b
    dec b
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $2706
    ld b, $27
    inc h
    ld bc, $0124
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $0505
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $0505
    dec b
    dec b
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $0505
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $2706
    ld b, $27
    inc h
    ld bc, $0124
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $0505
    db $10
    db $10
    dec b
    dec b
    db $10
    db $10
    dec b
    dec b
    dec b
    dec b
    ld b, $27
    dec b
    dec b
    inc h
    ld bc, $0505
    db $10
    db $10
    dec b
    dec b
    db $10
    db $10
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    ld [$0509], sp
    dec b
    jr @+$1b

    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    ld a, [bc]
    dec bc
    dec b
    dec b
    ld a, [de]
    dec de
    jr nz, jr_01b_54c2

    jr nz, jr_01b_54c4

    jr nz, jr_01b_54c6

    jr nz, jr_01b_54c8

    jr nz, @+$22

    ld a, [bc]
    dec bc
    jr nz, jr_01b_54ce

    ld a, [de]
    dec de
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10

jr_01b_54c2:
    db $10
    db $10

jr_01b_54c4:
    db $10
    db $10

jr_01b_54c6:
    db $10
    db $10

jr_01b_54c8:
    db $10
    ld h, $05
    dec b
    ld h, $31

jr_01b_54ce:
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    dec b
    dec b
    dec h
    db $10
    dec b
    dec b
    rla
    dec h
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    ld b, $27
    ld b, $27
    inc h
    ld bc, $0124
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec h
    db $10
    db $10
    db $10
    rla
    dec h
    db $10
    db $10
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    db $10
    db $10
    db $10
    ld h, $10
    db $10
    ld h, $31
    db $10
    db $10
    db $10
    ld h, $10
    db $10
    ld h, $31
    jr nz, jr_01b_554a

    ld sp, $2031
    jr nz, @+$33

    ld sp, $2020
    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    ld b, $27
    ld b, $27
    inc h
    ld bc, $0124
    rla
    rla
    jr nz, jr_01b_5564

    rla
    rla
    jr nz, jr_01b_5568

    rla
    rla

jr_01b_554a:
    jr nz, jr_01b_556c

    rla
    rla
    jr nz, jr_01b_5570

    jr nz, jr_01b_5572

    ld sp, $2031
    jr nz, jr_01b_5588

    ld sp, $2020
    ld sp, $2031
    jr nz, jr_01b_5590

    ld sp, $1717
    jr nz, jr_01b_5584

jr_01b_5564:
    rla
    rla
    jr nz, jr_01b_5588

jr_01b_5568:
    ld b, $27
    ld b, $27

jr_01b_556c:
    inc h
    ld bc, $0124

jr_01b_5570:
    jr nz, jr_01b_5592

jr_01b_5572:
    ld sp, $2031
    jr nz, jr_01b_55a8

    ld sp, $2706
    ld b, $27
    inc h
    ld bc, $0124
    inc c
    dec c
    jr nz, jr_01b_55a4

jr_01b_5584:
    inc e
    dec e
    jr nz, jr_01b_55a8

jr_01b_5588:
    inc c
    dec c
    inc c
    dec c
    inc e
    dec e
    inc e
    dec e

jr_01b_5590:
    ld [bc], a
    inc bc

jr_01b_5592:
    inc c
    dec c
    ld [de], a
    inc de
    inc e
    dec e
    ld [bc], a
    inc bc
    inc c
    dec c
    ld [de], a
    inc de
    inc e
    dec e
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01b_55a4:
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01b_55a8:
    ld [bc], a
    inc bc
    inc c
    dec c
    ld [de], a
    inc de
    inc e
    dec e
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    inc c
    dec c
    jr nz, jr_01b_55dc

    inc e
    dec e
    jr nz, jr_01b_55e0

    ld hl, $2021
    jr nz, jr_01b_55e6

    ld hl, $2020
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    inc c
    dec c
    inc c
    dec c
    inc e
    dec e
    inc e
    dec e
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc

jr_01b_55dc:
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01b_55e0:
    inc c
    dec c
    inc c
    dec c
    inc e
    dec e

jr_01b_55e6:
    inc e
    dec e
    inc c
    dec c
    inc c
    dec c
    inc e
    dec e
    inc e
    dec e
    ld [bc], a
    inc bc
    inc c
    dec c
    ld [de], a
    inc de
    inc e
    dec e
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    ld sp, $1528
    ld d, $28
    db $10
    dec d
    ld d, $20
    jr nz, jr_01b_562b

    jr nz, jr_01b_562d

    jr nz, jr_01b_562f

    jr nz, jr_01b_5621

    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    jr nz, jr_01b_563a

    jr nz, jr_01b_563c

    jr nz, jr_01b_563e

    jr nz, jr_01b_5640

    add hl, hl

jr_01b_5621:
    add hl, hl
    db $10
    db $10
    dec b
    dec b
    db $10
    db $10
    dec b
    dec b
    ld a, [hl+]

jr_01b_562b:
    ld a, [hl+]
    dec b

jr_01b_562d:
    dec b
    ld a, [hl+]

jr_01b_562f:
    ld a, [hl+]
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    ld [bc], a
    inc bc

jr_01b_563a:
    jr nz, jr_01b_565c

jr_01b_563c:
    ld [de], a
    inc de

jr_01b_563e:
    jr nz, jr_01b_5660

jr_01b_5640:
    rla
    rla
    ld [bc], a
    inc bc
    rla
    rla
    ld [de], a
    inc de
    ld de, $0217
    inc bc
    db $10
    ld de, $1312
    jr nz, jr_01b_5672

    ld [bc], a
    inc bc
    jr nz, jr_01b_5676

    ld [de], a
    inc de
    rlca
    jr nz, jr_01b_565d

    inc bc

jr_01b_565c:
    rla

jr_01b_565d:
    rlca
    ld [de], a
    inc de

jr_01b_5660:
    db $10
    db $10
    ld a, [hl+]
    ld a, [hl+]
    db $10
    db $10
    ld a, [hl+]
    ld a, [hl+]
    jr nz, jr_01b_568a

    jr nz, jr_01b_568c

    jr nz, jr_01b_568e

    jr nz, jr_01b_5690

    jr nz, @+$22

jr_01b_5672:
    jr nz, @+$22

    jr nz, jr_01b_5696

jr_01b_5676:
    jr nz, jr_01b_5698

    add hl, hl
    add hl, hl
    add hl, hl
    add hl, hl
    dec b
    dec b
    dec b
    dec b
    jr nz, jr_01b_56a2

    jr nz, jr_01b_56a4

    jr nz, jr_01b_56a6

    jr nz, jr_01b_56a8

    add hl, hl
    add hl, hl

jr_01b_568a:
    jr nz, jr_01b_56ac

jr_01b_568c:
    dec b
    dec b

jr_01b_568e:
    jr nz, jr_01b_56b0

jr_01b_5690:
    rlca
    jr nz, jr_01b_56b3

    jr nz, jr_01b_56ac

    rlca

jr_01b_5696:
    jr nz, jr_01b_56b8

jr_01b_5698:
    add hl, hl
    add hl, hl
    add hl, hl
    add hl, hl
    dec b
    dec b
    dec b
    dec b
    jr nz, jr_01b_56c2

jr_01b_56a2:
    jr nz, jr_01b_56c4

jr_01b_56a4:
    jr nz, jr_01b_56c6

jr_01b_56a6:
    jr nz, jr_01b_56c8

jr_01b_56a8:
    inc c
    dec c
    inc c
    dec c

jr_01b_56ac:
    inc e
    dec e
    inc e
    dec e

jr_01b_56b0:
    ld [bc], a
    inc bc
    ld [bc], a

jr_01b_56b3:
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01b_56b8:
    inc c
    dec c
    inc c
    dec c
    inc e
    dec e
    inc e
    dec e
    ld a, [hl+]
    ld a, [hl+]

jr_01b_56c2:
    ld a, [hl+]
    ld a, [hl+]

jr_01b_56c4:
    ld a, [hl+]
    ld a, [hl+]

jr_01b_56c6:
    ld a, [hl+]
    ld a, [hl+]

jr_01b_56c8:
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    dec b
    dec b
    ld a, [bc]
    dec bc
    dec b
    dec b
    ld a, [de]
    dec de
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
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
    ld a, [bc]
    dec bc
    ld [de], a
    inc de
    ld a, [de]
    dec de
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr nz, jr_01b_571a

    ld hl, $2021
    jr nz, jr_01b_5720

    ld hl, $2020
    add hl, hl
    add hl, hl
    jr nz, @+$22

    dec b
    dec b
    jr nz, @+$22

    dec b
    dec b
    jr nz, jr_01b_572e

    dec b
    dec b
    ld [bc], a
    inc bc
    dec hl
    inc l
    ld [de], a
    inc de
    dec l
    ld l, $02
    inc bc

jr_01b_571a:
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de

jr_01b_5720:
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    ld sp, $1528
    ld d, $28
    db $10

jr_01b_572e:
    dec d
    ld d, $20
    jr nz, jr_01b_5754

    ld hl, $2020
    ld hl, $2021
    jr nz, @+$04

    inc bc
    jr nz, jr_01b_575e

    ld [de], a
    inc de
    jr nz, jr_01b_5762

    jr nz, jr_01b_5764

    jr nz, jr_01b_5766

    jr nz, jr_01b_5768

    cpl
    cpl
    jr nz, jr_01b_576c

    ld [hl+], a
    ld [hl+], a
    jr nz, jr_01b_5770

    jr nz, jr_01b_5772

    jr nz, jr_01b_5774

jr_01b_5754:
    jr nz, jr_01b_5776

    jr nz, jr_01b_5778

    jr nz, jr_01b_577a

    cpl
    cpl
    jr nz, jr_01b_577e

jr_01b_575e:
    ld [hl+], a
    ld [hl+], a
    jr nz, jr_01b_5782

jr_01b_5762:
    jr nz, jr_01b_5784

jr_01b_5764:
    jr nz, jr_01b_5786

jr_01b_5766:
    jr nz, jr_01b_5788

jr_01b_5768:
    jr nz, @+$06

    add hl, hl
    add hl, hl

jr_01b_576c:
    inc b
    ld sp, $0505

jr_01b_5770:
    inc c
    dec c

jr_01b_5772:
    inc c
    dec c

jr_01b_5774:
    inc e
    dec e

jr_01b_5776:
    inc e
    dec e

jr_01b_5778:
    add hl, hl
    add hl, hl

jr_01b_577a:
    add hl, hl
    add hl, hl
    dec b
    dec b

jr_01b_577e:
    dec b
    dec b
    jr nz, jr_01b_57a2

jr_01b_5782:
    jr nz, jr_01b_57a4

jr_01b_5784:
    jr nz, jr_01b_57a6

jr_01b_5786:
    jr nz, jr_01b_57a8

jr_01b_5788:
    jr nz, jr_01b_57aa

    dec hl
    inc l
    jr nz, jr_01b_57ae

    dec l
    ld l, $0c
    dec c
    jr nz, jr_01b_57b4

    inc e
    dec e
    jr nz, jr_01b_57b8

    inc c
    dec c
    jr nz, @+$22

    inc e
    dec e
    jr nz, jr_01b_57c0

    inc c
    dec c

jr_01b_57a2:
    inc c
    dec c

jr_01b_57a4:
    inc e
    dec e

jr_01b_57a6:
    inc e
    dec e

jr_01b_57a8:
    jr nz, jr_01b_57ca

jr_01b_57aa:
    jr nz, jr_01b_57cc

    jr nz, jr_01b_57ce

jr_01b_57ae:
    jr nz, jr_01b_57d0

    jr nz, @+$22

    jr nz, jr_01b_57d4

jr_01b_57b4:
    jr nz, jr_01b_57d6

    jr nz, jr_01b_57d8

jr_01b_57b8:
    rlca
    jr nz, jr_01b_57db

    jr nz, jr_01b_57d4

    rlca
    jr nz, jr_01b_57e0

jr_01b_57c0:
    rla
    rla
    ld [bc], a
    inc bc
    rla
    rla
    ld [de], a
    inc de
    rla
    rla

jr_01b_57ca:
    ld [bc], a
    inc bc

jr_01b_57cc:
    rla
    rla

jr_01b_57ce:
    ld [de], a
    inc de

jr_01b_57d0:
    rlca
    jr nz, jr_01b_57d5

    inc bc

jr_01b_57d4:
    rla

jr_01b_57d5:
    rlca

jr_01b_57d6:
    ld [de], a
    inc de

jr_01b_57d8:
    rla
    rla
    ld [bc], a

jr_01b_57db:
    inc bc
    rla
    rla
    ld [de], a
    inc de

jr_01b_57e0:
    inc c
    dec c
    ld [bc], a
    inc bc
    inc e
    dec e
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
    rla
    rla
    jr nz, jr_01b_5814

    rla
    rla
    jr nz, jr_01b_5818

    rla
    rla
    jr nz, jr_01b_581c

    rla
    rla
    jr nz, jr_01b_5820

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    inc c
    dec c
    ld [bc], a
    inc bc
    inc e
    dec e
    ld [de], a
    inc de
    add hl, hl
    add hl, hl
    add hl, hl
    add hl, hl

jr_01b_5814:
    dec b
    dec b
    dec b
    dec b

jr_01b_5818:
    dec b
    dec b
    ld c, $0f

jr_01b_581c:
    dec b
    dec b
    ld e, $1f

jr_01b_5820:
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
    cpl
    cpl
    jr nz, @+$22

    ld [hl+], a
    ld [hl+], a
    jr nz, jr_01b_5858

    jr nz, jr_01b_585a

    jr nz, jr_01b_585c

    jr nz, jr_01b_585e

    jr nz, jr_01b_5860

    jr nz, jr_01b_5862

    cpl
    cpl
    jr nz, jr_01b_5866

    ld [hl+], a
    ld [hl+], a
    jr nz, jr_01b_586a

    jr nz, jr_01b_586c

    jr nz, jr_01b_586e

    jr nz, jr_01b_5870

    dec b
    dec b
    ld [$0509], sp
    dec b
    jr @+$1b

jr_01b_5858:
    db $10
    db $10

jr_01b_585a:
    db $10
    db $10

jr_01b_585c:
    db $10
    db $10

jr_01b_585e:
    db $10
    db $10

jr_01b_5860:
    inc c
    dec c

jr_01b_5862:
    inc c
    dec c
    inc e
    dec e

jr_01b_5866:
    inc e
    dec e
    jr nz, jr_01b_588a

jr_01b_586a:
    inc c
    dec c

jr_01b_586c:
    jr nz, jr_01b_588e

jr_01b_586e:
    inc e
    dec e

jr_01b_5870:
    ld sp, $0531
    dec b
    ld sp, $0531
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    add hl, hl
    add hl, hl
    add hl, hl
    add hl, hl
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b

jr_01b_588a:
    ld a, [bc]
    dec bc
    dec b
    dec b

jr_01b_588e:
    ld a, [de]
    dec de
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
    rla
    rla
    jr nz, jr_01b_58c4

    rla
    rla
    jr nz, jr_01b_58c8

    dec b
    dec b
    add hl, hl
    add hl, hl
    dec b
    dec b
    dec b
    dec b
    add hl, hl
    add hl, hl
    rlca
    jr nz, jr_01b_58ba

    dec b
    rla
    rlca
    ld a, [bc]
    dec bc

jr_01b_58ba:
    rla
    rla
    ld a, [de]
    dec de
    rla
    rla
    nop
    nop
    nop
    nop

jr_01b_58c4:
    nop
    nop
    nop
    nop

jr_01b_58c8:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, b
    nop
    and b
    nop
    ld d, b
    nop
    and b
    nop
    dec b
    nop
    ld a, [bc]
    nop
    dec b
    nop
    ld a, [bc]
    nop
    rrca
    rrca
    rra
    db $10
    ccf
    jr c, jr_01b_5966

    ld b, h
    ld c, a
    ld b, h
    ld c, h
    ld b, a
    db $fc
    add $c5
    rst $38
    ldh a, [$f0]
    ld hl, sp+$08
    db $f4
    inc b
    db $f4
    inc b
    db $f4
    inc b
    inc b
    db $fc
    and a
    xor a
    rst $30
    db $fd
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
    nop
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
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld d, b
    nop
    and b
    nop
    ld d, b
    nop
    and b
    nop
    ld a, a
    ld a, [hl]
    ld b, d
    ld b, d
    ld b, e
    ld e, d
    ld b, d
    ld b, d
    ld a, [hl]
    nop
    cp l
    nop
    db $db
    nop
    rst $20
    nop
    rst $38
    rra
    ldh [rNR41], a
    and a
    jr nz, jr_01b_59a6

    jr nz, jr_01b_59bf

    nop
    cp l
    nop
    db $db
    nop
    rst $20
    nop
    rst $38
    ld hl, sp+$07
    inc b
    push hl
    inc b
    and $04
    ld bc, $0201
    ld [bc], a
    dec b
    inc b
    dec bc
    ld [$1017], sp
    cpl
    jr nz, @+$61

    ld b, b
    cp a
    add b
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38

jr_01b_5966:
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
    rst $38
    rst $38
    ld e, a
    ld b, b
    rst $38
    ld a, a

jr_01b_59a6:
    cp a
    add b
    cp a
    add b
    add b
    rst $38
    cp a
    rst $38
    and b
    ldh [rIE], a
    rst $38
    rst $38
    inc bc
    rst $38
    rst $38
    rst $38
    ld bc, $01ff
    ld bc, $fdff
    rst $38
    dec b

jr_01b_59bf:
    rlca
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
    add b

jr_01b_59d3:
    rst $38
    ld a, a
    ld a, a
    ld b, a
    ld a, h
    ld a, a
    ld b, h
    ld a, a
    ld b, h
    ld a, a
    ld b, h
    jr c, jr_01b_5a18

    call nz, $c5fe
    rst $38
    call nz, $c4fe
    rst $38
    cp c
    cp a
    sub c
    sbc a
    adc a
    adc a
    add b
    add b
    and l
    xor a
    push af
    rst $38
    and l
    xor a
    dec b
    rst $38
    push bc
    rst $38
    rst $00
    db $fd
    rst $38
    ld sp, hl
    ld bc, $0001
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
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38

jr_01b_5a18:
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld b, d
    ld b, d
    jp nz, $425a

    ld b, d
    cp $7e
    ld bc, $aa00
    nop
    ld d, l
    nop
    rst $38
    rst $38
    ld h, a
    jr nz, jr_01b_59d3

    jr nz, @+$01

    jr nz, @+$01

    cpl
    ld hl, sp+$2f
    db $fc
    dec hl
    cp d
    dec a
    ld a, [hl]
    nop
    and $04
    dec b
    inc b
    rst $38
    inc b
    rst $38
    db $f4
    rra
    db $f4
    ccf
    call nc, $bc5d
    ld a, [hl]
    nop
    add b
    add b
    ld b, b
    ld b, b
    and b
    jr nz, @-$2e

    db $10
    add sp, $08
    db $f4
    inc b
    ld a, [$fd02]
    inc bc
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
    and b
    xor $a0
    ldh [$a0], a
    rst $28
    and a
    add sp, -$59
    add sp, -$41
    rst $38
    adc b
    rst $38
    rst $38
    rst $38
    ld h, l
    rlca
    ld h, l
    rlca
    dec b
    rst $30
    push hl
    rla
    push hl
    rla
    db $fd
    rst $38
    ld de, $ffff
    rst $38
    ld a, [hl]
    nop
    cp l
    nop
    db $db
    nop
    rst $20
    nop
    rst $20
    nop
    db $db
    nop
    cp l
    nop
    ld a, [hl]
    nop
    ld d, b
    nop
    and b
    nop
    ld d, b
    nop
    and b
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    rst $38
    rst $38
    cp a
    ret nz

    cp a
    rst $38
    cp a
    db $e4
    and h
    db $e4
    and h
    db $e4
    cp a
    rst $38
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
    sbc a
    sbc a
    ldh [$b0], a
    add sp, -$49
    rst $28
    cp a
    ldh [$a0], a
    rst $20
    xor b
    ldh [$a0], a
    rst $38
    rst $38
    ret nz

    ret nz

    ccf
    ld h, b
    cp a
    ld h, b
    cp a
    ldh [$3f], a
    jr nz, jr_01b_5b5c

    and b
    ccf
    jr nz, @+$01

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
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
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
    ld bc, $fd01
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc

jr_01b_5b5c:
    db $fd
    inc bc
    db $fd
    inc bc
    cp a
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
    dec e
    dec e
    and $e6
    cp a
    rst $38
    and [hl]
    and $bf
    rst $38
    and [hl]
    and $ff
    rst $38
    nop
    nop
    rst $38
    rst $18
    ld sp, $ff20
    rst $38
    ld sp, $ff20
    rst $38
    ld sp, $ff20
    rst $38
    nop
    nop
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
    ld bc, $ff01
    rst $38
    add b
    add b
    xor b
    xor b
    xor l
    xor l
    add b
    add b
    cp a
    cp a
    add b
    add b
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $2d01
    dec l
    xor c
    xor c
    ld bc, $fd01
    db $fd
    ld bc, $ff01
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    ld bc, $ffff
    rst $38
    ld bc, $ffff
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    ld bc, $ffff
    rst $38

jr_01b_5be0:
    add b
    rst $38
    rst $38
    rst $38
    cp a
    sbc b
    cp a
    sbc b
    cp b
    sbc a
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    ld a, a
    ld bc, $ffff
    rst $38
    db $fd
    add hl, de
    db $fd
    add hl, de
    dec e
    ld sp, hl
    rst $38
    rst $38
    ld bc, $ffff
    cp $e0
    cp a
    sbc a
    rst $38
    ret nc

    cp a
    rst $38
    sub c
    rst $38
    adc [hl]
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    ccf
    db $ec
    db $d3
    ld a, [c]
    ld h, c
    xor e
    pop bc
    pop bc
    add a
    or [hl]
    adc a
    cp b
    rst $08
    ld c, b
    rst $38
    jr nc, jr_01b_5be0

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
    push de
    xor e
    xor e
    push de
    push de
    xor e
    xor e
    push de
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
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
    adc [hl]
    rst $38
    inc b
    adc [hl]
    inc b
    ld [hl], l
    adc [hl]
    adc [hl]
    rst $38
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    ccf
    rst $38
    ld de, $1f31
    pop de
    ld sp, $ff3f
    rst $38
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
    add c
    add c
    add c
    xor l
    add c
    xor l
    add c
    add c
    add c
    xor l
    add c
    xor l
    add c
    add c
    add c
    add c
    add c
    xor l
    add c
    xor l
    add c
    add c
    rst $38
    rst $38
    xor d
    nop
    ld d, l
    nop
    rst $38
    rst $38
    add b
    add b
    rst $38
    rst $38
    cp a
    rst $38
    pop hl
    or e
    rst $38
    cp a
    rst $38
    and c
    cp a

jr_01b_5ccd:
    rst $38
    add b
    add b
    nop
    nop
    rst $38
    rst $38
    daa
    rst $38
    ld h, $ff
    daa
    daa
    ld h, $26
    rst $38

jr_01b_5cdd:
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    ld hl, $ff33

jr_01b_5ce9:
    rst $38
    ld h, e
    ld hl, $ffff
    nop
    nop
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
    ld bc, $ff01
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    and l
    rst $38
    jp $e37e


    cp l
    ld a, [hl]
    db $db
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add b
    cp a
    ret nz

    ld e, a
    ld h, b
    cpl
    jr nc, jr_01b_5d40

    jr @+$0d

    inc c
    dec b
    ld b, $02
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    ld a, [$f406]
    inc c
    add sp, $18
    ret nc

    jr nc, jr_01b_5cdd

    ld h, b
    ld b, b
    ret nz

jr_01b_5d40:
    nop
    rst $38
    nop
    add b
    jr c, jr_01b_5ccd

    jr nc, @-$6f

    jr nz, jr_01b_5ce9

    nop
    cp a
    ld bc, $00be
    add b
    nop
    rst $38
    nop
    ld bc, $fd00
    nop
    db $fd
    ld b, b
    cp l
    ldh [rNR33], a
    ldh a, [$0d]
    nop
    ld bc, $ffaa
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    or b
    sbc a
    ld a, a
    rst $38
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    dec c
    ld sp, hl
    cp $ff
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
    rst $38
    rst $38
    ld b, h
    rst $38
    db $fc
    ld b, a
    ld b, a
    ld b, a
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
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
    inc a
    rst $20
    inc a
    rst $20
    ld a, [hl]
    db $db
    rst $20
    cp l
    ld b, e
    ld a, [hl]
    and l
    cp l
    jp c, $ff5a

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
    nop
    rst $38
    rst $38
    rst $38
    cp h
    rst $00
    cp a
    jp Jump_01b_4070


    jr nz, jr_01b_5e4c

    jr jr_01b_5e46

    rlca
    rlca
    nop
    rst $38
    rst $38
    rst $38
    ccf
    pop hl
    rst $38
    pop bc
    ld c, $02
    inc b
    inc b
    jr jr_01b_5e56

    ldh [$f0], a
    nop
    or b
    nop
    or l
    nop
    xor l

jr_01b_5e46:
    nop
    add b
    nop
    rst $38
    xor d
    nop

jr_01b_5e4c:
    ld d, l
    nop
    rst $38
    rst $38
    nop
    dec c
    nop
    xor l
    nop
    or l

jr_01b_5e56:
    nop
    ld bc, $ff00
    xor d
    nop
    ld d, l
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
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
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld hl, $2121
    ld hl, $0101
    ld bc, $0101
    ld bc, $0101
    inc c
    dec c
    ld bc, $1c01
    dec e
    ld hl, $0121
    ld bc, $0101
    ld bc, $0101
    ld bc, $0b0a
    ld bc, $1a01
    dec de
    ld hl, $2421
    dec h
    ld c, $0f
    inc [hl]
    dec [hl]
    ld e, $1f
    jr nc, @+$17

    dec d
    dec d
    jr nz, jr_01b_5f0e

    jr nz, jr_01b_5f10

    daa
    daa
    inc h
    dec h
    scf
    scf
    inc [hl]
    dec [hl]
    dec d
    dec d
    dec d
    dec d
    jr nz, jr_01b_5f1e

    jr nz, jr_01b_5f20

    ld c, $0f
    jr nz, jr_01b_5f24

    ld e, $1f
    jr nz, jr_01b_5f28

    dec d
    ld sp, $2020
    jr nz, jr_01b_5f2e

jr_01b_5f0e:
    jr nz, jr_01b_5f30

jr_01b_5f10:
    ld bc, $0101
    ld bc, $0101
    ld bc, $0201
    inc bc
    ld [bc], a
    inc bc
    ld [de], a
    inc de

jr_01b_5f1e:
    ld [de], a
    inc de

jr_01b_5f20:
    jr nz, jr_01b_5f42

    jr nz, jr_01b_5f44

jr_01b_5f24:
    jr nz, jr_01b_5f46

    jr nz, jr_01b_5f48

jr_01b_5f28:
    inc b
    inc b
    inc b
    inc b
    inc d
    inc d

jr_01b_5f2e:
    inc d
    inc d

jr_01b_5f30:
    jr nz, jr_01b_5f52

    rlca
    ld [$2020], sp
    rla
    jr @+$22

    jr nz, jr_01b_5f42

    ld [$2020], sp
    rla
    jr @+$2c

    dec hl

jr_01b_5f42:
    inc l
    dec l

jr_01b_5f44:
    ld a, [hl-]
    dec sp

jr_01b_5f46:
    inc a
    dec a

jr_01b_5f48:
    ld b, b
    ld b, c
    ld b, d
    ld b, e
    ld d, b
    ld d, c
    ld d, d
    ld d, e
    jr nz, @+$22

jr_01b_5f52:
    jr nz, jr_01b_5f74

    jr nz, @+$22

    jr nz, @+$22

    jr nz, jr_01b_5f7a

    jr nz, @+$22

    jr nz, @+$22

    jr nz, jr_01b_5f80

    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $2828
    ld hl, $3821
    jr c, @+$03

    ld bc, $0101

jr_01b_5f74:
    ld bc, $0101
    ld bc, $0106

jr_01b_5f7a:
    ld bc, $1601
    ld hl, $2121

jr_01b_5f80:
    ld bc, $0101
    ld bc, $0101
    ld bc, $0e01
    rrca
    ld c, $0f
    ld e, $1f
    ld e, $1f
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    ld h, $27
    daa
    daa
    ld [hl], $39
    dec d
    dec d
    ld [hl], $39
    jr nz, jr_01b_5fcc

    ld [hl], $39
    jr nz, jr_01b_5fd0

    daa
    daa
    daa
    daa
    dec d
    dec d
    dec d
    dec d
    jr nz, jr_01b_5fda

    jr nz, jr_01b_5fdc

    jr nz, jr_01b_5fde

    jr nz, jr_01b_5fe0

    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    jr nz, jr_01b_5fea

    jr nz, jr_01b_5fec

jr_01b_5fcc:
    jr nz, jr_01b_5fee

    jr nz, jr_01b_5ff0

jr_01b_5fd0:
    jr nz, jr_01b_5ff2

    jr nz, jr_01b_5ff4

    jr nz, jr_01b_5ff6

    jr nz, jr_01b_5ff8

    jr nz, jr_01b_5ffa

jr_01b_5fda:
    jr nz, jr_01b_5ffc

jr_01b_5fdc:
    jr nz, jr_01b_5ffe

jr_01b_5fde:
    jr nz, jr_01b_6000

jr_01b_5fe0:
    ld [hl], $39
    jr nz, jr_01b_6004

    ld [hl], $39
    jr nz, @+$22

    ld [hl], $39

jr_01b_5fea:
    jr nz, jr_01b_600c

jr_01b_5fec:
    ld [hl], $39

jr_01b_5fee:
    jr nz, jr_01b_6010

jr_01b_5ff0:
    ld h, $27

jr_01b_5ff2:
    daa
    daa

jr_01b_5ff4:
    jr nc, @+$17

jr_01b_5ff6:
    dec d
    dec d

jr_01b_5ff8:
    jr nz, jr_01b_601a

jr_01b_5ffa:
    jr nz, jr_01b_601c

jr_01b_5ffc:
    jr nz, jr_01b_601e

jr_01b_5ffe:
    jr nz, jr_01b_6020

jr_01b_6000:
    daa
    daa
    daa
    add hl, hl

jr_01b_6004:
    dec d
    dec d
    dec d
    ld sp, $2020
    jr nz, jr_01b_602c

jr_01b_600c:
    jr nz, jr_01b_602e

    jr nz, @+$22

jr_01b_6010:
    jr nz, @+$22

    ld [hl], $39
    jr nz, @+$22

    ld [hl], $39
    jr nz, jr_01b_603a

jr_01b_601a:
    ld [hl], $39

jr_01b_601c:
    jr nz, @+$22

jr_01b_601e:
    ld [hl], $39

jr_01b_6020:
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101

jr_01b_602c:
    ld h, $29

jr_01b_602e:
    ld hl, $0121
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101

jr_01b_603a:
    ld bc, $2101
    ld hl, $2926
    jr nz, jr_01b_6062

    jr nz, jr_01b_6064

    jr nz, jr_01b_6066

    jr nz, jr_01b_6068

    ld a, [hl+]
    dec hl
    inc l
    dec l
    ld a, [hl-]
    dec sp
    inc a
    dec a
    ld h, $29
    ld h, $29
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld b, h
    ld b, h

jr_01b_6062:
    ld b, h
    ld b, h

jr_01b_6064:
    ld d, h
    ld d, h

jr_01b_6066:
    ld d, h
    ld d, h

jr_01b_6068:
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    add hl, bc
    daa
    daa
    add hl, de
    ld [hl], $37
    scf
    add hl, sp
    ld b, [hl]
    scf
    scf
    ld b, a
    ld d, l
    ld d, [hl]
    ld d, a
    scf
    ld b, b
    ld b, c
    ld b, d
    ld b, e
    ld d, b
    ld d, c
    ld d, d
    ld d, e
    jr nz, jr_01b_60aa

    jr nz, jr_01b_60ac

    jr nz, jr_01b_60ae

    jr nz, jr_01b_60b0

    rlca
    ld [$4537], sp
    rla
    jr jr_01b_60dc

    scf
    rlca
    ld [$4537], sp
    rla
    jr @+$47

    scf
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    scf
    ld b, l

jr_01b_60aa:
    scf
    ld b, l

jr_01b_60ac:
    ld b, l
    scf

jr_01b_60ae:
    ld b, l
    scf

jr_01b_60b0:
    scf
    ld b, l
    rlca
    ld [$3745], sp
    rla
    jr @+$39

    ld b, l
    rlca
    ld [$3745], sp
    rla
    jr @+$03

    ld bc, $0101
    ld bc, $0101
    ld bc, $2926
    ld h, $29
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    scf
    ld b, l
    scf
    ld b, l

jr_01b_60dc:
    ld b, l
    scf
    ld b, l
    scf
    ld bc, $0101
    ld bc, $0101
    ld bc, $4801
    ld c, c
    ld bc, $5801
    ld e, c
    ld hl, $0121
    ld bc, $0101
    ld bc, $0101
    ld bc, $2f2e
    ld bc, $2101
    ld hl, $2121
    daa
    daa
    ld l, $2f
    dec d
    dec d
    dec d
    ld sp, $2020
    jr nz, jr_01b_612c

    jr nz, jr_01b_612e

    jr nz, jr_01b_6130

    daa
    daa
    daa
    add hl, hl
    dec d
    dec d
    ld [hl], $39
    jr nz, jr_01b_613a

    ld [hl], $39
    jr nz, jr_01b_613e

    ld [hl], $39
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    scf
    ld b, l
    inc b
    inc b

jr_01b_612c:
    ld b, l
    scf

jr_01b_612e:
    inc d
    inc d

jr_01b_6130:
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    inc b
    inc b

jr_01b_613a:
    scf
    ld b, l
    inc d
    inc d

jr_01b_613e:
    ld b, l
    scf
    ld bc, $0101
    ld bc, $2121
    ld hl, $3721
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld bc, $3e01
    ld bc, $2121
    ccf
    ld hl, $4537
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld bc, $0101
    ld bc, $2121
    ld hl, $0721
    ld [$0807], sp
    rla
    jr jr_01b_6186

    jr @+$09

    ld [$0807], sp
    rla
    jr jr_01b_618e

    jr @+$0b

    daa
    daa
    add hl, de
    ld [hl], $37
    scf
    add hl, sp
    ld bc, $0101
    ld bc, $2121

jr_01b_6186:
    ld hl, $3721
    ld b, l
    rlca
    ld [$3745], sp

jr_01b_618e:
    rla
    jr @+$39

    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    daa
    daa
    daa
    daa
    dec d
    dec d
    dec d
    dec d
    ld bc, $0101
    ld bc, $2121
    ld hl, $2021
    jr nz, @+$22

    jr nz, @+$22

    jr nz, @+$22

    jr nz, jr_01b_61f7

    scf
    scf
    ld b, a
    ld d, l
    ld d, [hl]
    ld d, a
    scf
    rlca
    ld [$0807], sp
    rla
    jr jr_01b_61d6

    jr @+$03

    ld bc, $0101
    ld h, $29
    ld hl, $3621
    add hl, sp
    jr nz, jr_01b_61ec

    ld [hl], $39
    jr nz, jr_01b_61f0

    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf

jr_01b_61d6:
    ld b, l
    scf
    daa
    daa
    daa
    add hl, hl
    dec d
    dec d
    dec d
    dec d
    ld bc, $4801
    ld c, c
    ld hl, $5821
    ld e, c
    scf
    ld b, l
    scf
    ld b, l

jr_01b_61ec:
    ld b, l
    scf
    ld b, l
    scf

jr_01b_61f0:
    jr z, jr_01b_621a

    ld bc, $3801
    jr c, jr_01b_6218

jr_01b_61f7:
    ld hl, $4537
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld c, a
    ld c, a
    ld c, a
    ld c, h
    ld c, a
    ld c, a
    ld c, a
    ld c, h
    ld c, a
    ld c, a
    ld c, a
    ld c, h
    ld c, a
    ld c, a
    ld c, a
    ld c, h
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf

jr_01b_6218:
    ld b, h
    ld b, h

jr_01b_621a:
    ld b, h
    ld b, h
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld c, e
    ld c, h
    ld c, e
    ld c, h
    ld c, e
    ld c, h
    ld c, e
    ld c, h
    ld c, e
    ld c, h
    ld c, e
    ld c, h
    ld c, l
    ld c, [hl]
    ld c, l
    ld c, [hl]
    ld [hl], $39
    ld [hl], $39
    ld [hl], $39
    ld [hl], $39
    ld [hl], $39
    ld [hl], $39
    ld [hl], $39
    ld [hl], $39
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld h, $29
    ld h, $29
    ld [hl], $39
    ld [hl], $39
    daa
    add hl, hl
    scf
    scf
    ld [hl], $39
    scf
    scf
    ld h, $29
    scf
    scf
    ld [hl+], a
    inc hl
    ld e, e
    ld e, e
    ld [hl+], a
    inc hl
    ld l, $2f
    ld [hl-], a
    inc sp
    ld hl, $3721
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    inc b
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    daa
    daa
    daa
    daa
    dec d
    dec d
    dec d
    dec d
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    ld a, [bc]
    dec bc
    ld e, e
    ld e, e
    ld c, e
    ld c, a
    ld c, a
    ld c, a
    ld c, e
    ld c, a
    ld c, a
    ld c, a
    ld c, e
    ld c, a
    ld c, a
    ld c, a
    ld c, e
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld bc, $0a01
    dec bc
    ld hl, $1a21
    dec de
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    ld c, e
    ld c, h
    ld bc, $4b3e
    ld c, h
    ld hl, $5c3f
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    ld bc, $0101
    ld bc, $2121
    ld hl, $3721
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    ld bc, $4b01
    ld c, h
    ld hl, $4b21
    ld c, h
    ld c, e
    ld c, h
    scf
    ld b, l
    ld c, e
    ld c, h
    ld b, l
    scf
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    scf
    ld b, l
    ld c, e
    ld c, h
    ld b, l
    scf
    ld c, e
    ld c, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    ld c, e
    ld c, h
    scf
    ld b, l
    ld c, e
    ld c, h
    ld b, l
    scf
    ld c, e
    ld c, h
    scf
    ld b, l
    ld c, e
    ld c, h
    ld b, l
    scf
    scf
    ld b, l
    ld c, e
    ld c, h
    ld b, l
    scf
    ld c, e
    ld c, h
    scf
    ld b, l
    ld c, e
    ld c, h
    ld b, l
    scf
    ld c, e
    ld c, h
    inc b
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    scf
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    jr z, jr_01b_63a2

    jr z, jr_01b_63a4

    jr c, @+$3a

    jr c, jr_01b_63b8

    scf
    ld b, l
    ld bc, $4501
    scf
    ld hl, $3721
    ld b, l
    scf
    ld b, l
    ld b, l
    scf
    ld b, l
    scf
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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

jr_01b_63a2:
    rst $38
    rst $38

jr_01b_63a4:
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
    inc bc
    inc bc
    inc b
    inc b
    ld [$0809], sp
    dec bc

jr_01b_63b8:
    ld [$080b], sp
    add hl, bc
    inc b
    inc b
    inc bc
    inc bc
    ret nz

    ret nz

    jr nz, jr_01b_63e4

    db $10
    sub b
    db $10
    ret nc

    db $10
    ret nc

    db $10
    sub b
    jr nz, jr_01b_63ee

    ret nz

    ret nz

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
    rst $38
    rst $38
    add b
    add b

jr_01b_63e4:
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

jr_01b_63ee:
    cp a
    cp a
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
    nop
    nop
    nop
    nop
    rrca
    rrca
    rla
    jr jr_01b_6438

    jr nc, jr_01b_643a

    jr nc, jr_01b_643c

    jr nc, jr_01b_6436

    jr c, jr_01b_6466

    nop
    xor d
    nop
    push af
    ldh a, [$ea]
    jr @-$09

    inc c
    db $f4
    inc c
    push af
    inc c
    db $e4
    inc e
    ld a, a
    ld a, a
    add b
    add b
    cp a
    or b
    cp a
    or b
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
    nop
    nop
    rst $38
    nop

jr_01b_6436:
    rst $38
    nop

jr_01b_6438:
    rst $38
    nop

jr_01b_643a:
    rst $38
    nop

jr_01b_643c:
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    add c
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
    cp $fe
    ld bc, $fd01
    dec c
    db $fd
    dec c
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_6466:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, a
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    nop
    nop
    cp $fe
    ld [bc], a
    cp $02
    cp $02
    cp $02
    cp $02
    cp $3a
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
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    ret nz

    nop
    nop
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    inc bc
    nop
    nop
    rst $38
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
    call c, $bfbf
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

jr_01b_64fa:
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    jr nz, jr_01b_6541

    sub b
    rra
    rrca
    rrca
    xor e
    ld a, [bc]
    ld [de], a
    ld [de], a
    or b
    ld de, $0858
    xor a
    rlca
    inc b
    db $fc
    ld [$f0f8], sp
    ldh a, [$d0]
    ld d, b
    ld c, b
    ld c, b
    ld [$1088], sp
    db $10
    ldh [$e0], a
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

Jump_01b_652f:
    add b
    rst $38
    jr c, jr_01b_64fa

    ld b, h
    cp e
    cp d
    cp e
    cp e
    rst $00
    add c
    db $fd
    add l
    ld a, a
    add $39
    cp $00

jr_01b_6541:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
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
    xor d
    nop
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ld b, b
    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ld a, a
    rst $38
    ld a, [hl+]
    xor $2a
    xor $3a
    xor $3b
    xor $13
    cp $03
    cp $03
    cp $fe
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
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $fdfd
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
    ld bc, $0101
    rst $38
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    ld d, l
    rst $38
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    ld d, l
    rst $38
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
    nop
    rst $38
    cp a
    cp a
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
    rst $38
    rst $38
    db $fd
    db $fd
    db $fc
    db $fc
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
    rst $38
    ld bc, $fdff
    rst $38
    db $fd
    and a
    and l
    and a
    db $fd
    rst $38
    db $fd
    rst $38
    dec b
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
    cp l
    ld a, [hl]
    ld h, [hl]
    jp $99ff


    rst $20
    and l
    ld a, [hl]
    db $db
    ld h, [hl]
    rst $20
    ld a, [hl]
    db $db
    ld h, [hl]
    rst $20
    rst $38
    rst $38
    add b
    add b
    or b
    cp a
    or b
    or b
    adc a
    and b
    adc a
    and b
    adc a
    and b
    adc a
    and b
    rst $38
    rst $38
    ld bc, $0d01
    rst $38
    dec c
    rrca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    add b
    add b
    rst $38
    rst $38
    rst $38
    ret nz

    add b
    add b
    rst $38
    rst $38
    ld bc, $0101
    ld bc, $ffff
    ld bc, $ff01
    rst $38
    rst $38
    pop bc
    ld bc, $ff01
    rst $38
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
    add b
    add b
    add b
    rst $38
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
    nop
    nop
    rst $38
    inc a
    db $db
    ld e, d
    add c
    sbc c
    jp $c3ff


    rst $38
    add c
    sbc c
    db $db
    ld e, d
    rst $38
    inc a
    rst $38
    rst $38
    add b
    rst $38
    cp a
    rst $38
    cp a
    db $e4
    and h
    db $e4
    cp a
    rst $38
    cp a
    rst $38
    and b
    rst $38
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
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    add h
    rst $38
    add a
    rst $38
    add b
    rst $38
    add b
    rst $38
    rst $38
    ld a, a
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld hl, $e1ff
    rst $38
    ld bc, $01ff
    rst $38
    rst $38
    cp $7e
    db $db
    ld h, [hl]
    rst $20
    ld a, [hl]
    db $db
    ld a, [hl]
    rst $38
    ld h, [hl]
    jp $bdc3


    db $db
    cp l
    rst $38
    rst $38
    adc a
    and b
    or b
    cp a
    or b
    cp a
    cp a
    add b
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    ld sp, hl
    rlca
    dec c
    rst $38
    dec c
    rst $38
    db $fd
    inc bc
    ld bc, $01ff
    rst $38
    ld bc, $ffff
    rst $38
    rst $38
    nop
    rst $38
    inc bc
    db $fc
    inc c
    ldh a, [rNR13]
    db $e3
    cpl
    push hl
    inc l
    rst $08
    ld d, h
    rst $08
    ld d, e
    rst $38
    nop
    rst $38
    ret nz

    ccf
    jr nc, jr_01b_6816

    add sp, -$49
    sub h
    rst $30
    sub h
    di
    ld a, [$6a9b]
    db $10
    rra
    db $10
    rra
    rra
    rra
    rra
    db $10
    cpl
    jr nc, jr_01b_67ea

    jr nc, jr_01b_67ec

    jr nc, jr_01b_67e6

    jr c, jr_01b_67ce

    ld hl, sp+$0a
    ld hl, sp-$03
    ld hl, sp-$06
    ld [$0cf5], sp
    db $f4
    inc c
    push af
    inc c

jr_01b_67ce:
    db $e4
    inc e
    rst $38
    inc a
    jp $df42


    add c
    jp $df81


    add c
    jp $8381


    db $fd
    rst $38
    rst $38
    rst $38
    ld a, b
    add a
    add h
    rst $30
    ld [bc], a

jr_01b_67e6:
    add a
    ld [bc], a
    rst $30
    ld [bc], a

jr_01b_67ea:
    add a
    ld [bc], a

jr_01b_67ec:
    add e
    ld a, [hl]
    rst $38
    cp $7f
    ld a, a
    add b
    add b
    sbc a
    xor a
    cp b
    sub b
    cp b
    sub b
    cp b
    sub b
    cp a
    cp a
    ret nz

    ret nz

    rst $38
    rst $38
    nop
    nop
    db $fd
    ld a, [$040f]
    rrca
    inc b
    rrca
    inc b
    rst $38
    cp $01
    ld bc, $0000
    inc bc
    inc bc
    inc c
    rrca

jr_01b_6816:
    db $10
    rra
    jr nz, jr_01b_6859

    inc hl
    ccf
    inc h
    ccf
    jr c, jr_01b_685f

    ld d, l
    nop
    xor d
    add b
    ld [hl], l
    ldh [rNR30], a
    ldh a, [$0d]
    ld hl, sp-$76
    ld hl, sp+$4d
    ld hl, sp+$3a
    ld hl, sp+$55
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    ld d, l
    rst $38
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    ld d, l
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_6859:
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_685f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rst $08
    ld d, c
    rst $20
    add hl, hl
    db $e3
    inc l
    ret nc

    inc sp
    db $ec
    inc e
    di
    rrca
    rst $38
    nop
    rst $38
    nop
    dec hl
    jp c, $ac5f

    rst $30
    db $f4
    dec bc

jr_01b_68a7:
    call z, Call_000_3837
    rst $08
    ldh a, [rIE]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_68cc:
    nop
    nop
    nop
    nop
    rrca
    rrca
    rla
    jr jr_01b_68cc

    ld hl, sp+$10
    rra
    ldh a, [rIE]
    ldh a, [$df]
    db $10
    rra
    ldh a, [rIE]
    ldh a, [$f0]
    add sp, $18
    rst $28
    rra
    ld [$0ff8], sp
    rst $38
    rrca
    ld hl, sp+$08
    ld hl, sp+$0f
    rst $38
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
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld l, h
    cpl
    and e
    inc hl
    ld h, b
    jr nc, jr_01b_68a7

    inc a
    ld d, b
    inc sp
    xor h
    inc e
    ld d, e
    rrca
    xor d
    nop
    ld l, b
    add sp, -$78
    adc b
    ld [$1018], sp
    ld a, b
    db $10
    sbc b
    ld h, b
    ld [hl], b
    add b
    ldh [rP1], a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    inc sp
    inc sp
    inc sp
    dec d
    ld bc, $0101
    dec d
    ld bc, $0101
    dec d
    ld bc, $0101
    inc sp
    inc sp
    inc sp
    inc sp
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    inc sp
    inc sp
    inc sp
    ld b, $01
    ld bc, $1601
    ld bc, $0101
    ld d, $01
    ld bc, $1601
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    ld bc, $0101
    ld bc, $1111
    ld de, $0211
    inc bc
    db $10
    db $10
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    add hl, bc
    ld a, [bc]
    ld a, [bc]
    inc c
    add hl, de
    ld a, [de]
    inc l
    inc e
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    dec c
    dec e
    rlca
    ld [$0d1d], sp
    rla
    jr @+$0f

    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    rlca
    ld [$1d0d], sp
    rla
    jr jr_01b_69dc

    dec c
    ld c, $0f
    db $10
    db $10
    ld e, $1f
    ld [de], a
    inc de
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    ld [bc], a
    inc bc
    db $10
    db $10
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec c
    dec e
    dec c
    dec e

jr_01b_69dc:
    dec e
    dec c
    dec e
    dec c
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0115
    ld bc, $1501
    ld bc, $0101
    dec d
    ld bc, $0101
    dec d
    ld bc, $0101
    ld bc, $0101
    ld d, $01
    ld bc, $1601
    ld bc, $0101
    ld d, $01
    ld bc, $1601
    dec d
    ld bc, $0101
    ld [hl-], a
    ld de, $1111
    jr nz, jr_01b_6a3a

    db $10
    db $10
    jr nc, @+$15

    ld [de], a
    inc de
    inc hl
    inc b
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    inc hl
    inc b

jr_01b_6a3a:
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    ld bc, $0101
    ld bc, $0101
    ld bc, $1501
    ld bc, $0101
    dec d
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $1601
    ld bc, $0101
    ld d, $01
    ld bc, $1601
    ld de, $1111
    ld [hl+], a
    db $10
    db $10
    db $10
    ld hl, $1312
    ld [de], a
    ld sp, $0633
    inc b
    inc b
    ld bc, $4a16
    ld c, d
    ld bc, $3326
    inc sp
    ld bc, $0101
    ld bc, $3305
    inc sp
    inc sp
    dec d
    ld bc, $0101
    dec h
    ld bc, $0101
    ld bc, $0101
    ld bc, $0404
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    daa
    jr z, jr_01b_6ab1

    inc b
    scf
    jr c, jr_01b_6ada

jr_01b_6ab1:
    ld a, [hl+]
    inc b
    inc b
    add hl, sp
    ld a, [hl-]
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    ld bc, $0101
    ld bc, $1111
    ld de, $0211
    inc bc
    ld c, $0f
    ld [de], a
    inc de
    ld e, $1f
    daa
    jr z, jr_01b_6ad7

    inc b
    scf
    jr c, jr_01b_6adb

jr_01b_6ad7:
    inc b
    inc hl
    inc b

jr_01b_6ada:
    inc b

jr_01b_6adb:
    inc b
    inc hl
    inc b
    inc b
    inc b
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    inc h
    inc h
    inc h
    inc h
    inc [hl]
    inc [hl]
    inc [hl]
    inc [hl]
    jr nz, jr_01b_6b02

    db $10
    ld hl, $1330
    ld [de], a
    ld sp, $0404
    daa
    jr z, jr_01b_6b01

    inc b
    scf
    jr c, jr_01b_6b11

jr_01b_6b01:
    db $10

jr_01b_6b02:
    db $10
    ld hl, $1312
    ld [de], a
    ld sp, $0404
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc d

jr_01b_6b11:
    inc d
    ld l, $2f
    inc d
    inc d
    ld a, $3f
    ld l, $2f
    ld l, $2f
    ld a, $3f
    ld a, $3f
    ld l, $2f
    inc hl
    inc hl
    ld a, $3f
    inc hl
    inc b
    inc hl
    inc hl
    inc hl
    inc b
    inc hl
    inc b
    inc b
    inc b
    ld l, $2f
    inc hl
    inc hl
    ld a, $3f
    inc hl
    inc b
    ld l, $2f
    inc hl
    inc b
    ld a, $3f
    inc hl
    inc b
    ld l, $2f
    ld l, $2f
    ld a, $3f
    ld a, $3f
    ld bc, $2e01
    cpl
    ld bc, $3e01
    ccf
    inc hl
    inc b
    inc b
    inc b
    inc hl
    inc b
    inc b
    inc b
    ld l, $2f
    inc hl
    inc b
    ld a, $3f
    inc hl
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
    inc d
    inc d
    inc d
    inc d
    inc hl
    inc hl
    inc hl
    inc hl
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    ld l, $2f
    ld l, $2f
    ld a, $3f
    ld a, $3f
    ld bc, $0101
    ld bc, $0101
    ld bc, $1401
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld l, $2f
    ld l, $2f
    ld a, $3f
    ld a, $3f
    dec l
    inc hl
    inc b
    inc b
    dec a
    inc hl
    inc b
    inc b
    dec l
    inc hl
    inc b
    inc b
    dec a
    inc hl
    inc b
    inc b
    ld bc, $0101
    ld bc, $0101
    ld bc, $1401
    inc d
    ld bc, $1401
    inc d
    ld bc, $2301
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    add hl, de
    ld b, b
    ld b, c
    inc e
    add hl, de
    ld d, b
    ld d, c
    inc e
    add hl, de
    inc l
    ld a, [de]
    inc e
    add hl, de
    inc l
    inc l
    inc e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    inc l
    ld b, b
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    inc l
    inc l
    inc l
    ld a, [de]
    inc l
    add hl, de
    inc l
    inc l
    inc e
    dec bc
    dec sp
    inc a
    dec bc
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    inc l
    dec [hl]
    dec [hl]
    inc l
    inc l
    dec [hl]
    dec [hl]
    inc l
    inc l
    inc l
    inc l
    inc l
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    daa
    jr z, jr_01b_6c28

    dec e
    scf
    jr c, jr_01b_6c3c

    dec c
    ld [bc], a
    inc bc
    add hl, bc
    inc c
    ld [de], a
    inc de
    ld [hl], $2b

jr_01b_6c28:
    ld c, b
    ld c, c
    ld [hl], $2b
    ld e, b
    ld e, c
    ld [hl], $2b
    ld [bc], a
    inc bc
    db $10
    db $10
    ld [de], a
    inc de
    ld d, h
    ld d, l
    dec c
    dec e
    ld b, d
    ld b, e

jr_01b_6c3c:
    dec e
    dec c
    rla
    jr jr_01b_6c43

    inc bc
    db $10

jr_01b_6c43:
    db $10
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    add hl, bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    add hl, de
    inc l
    ld b, h
    ld b, l
    add hl, de
    inc l
    inc l
    inc l
    dec sp
    inc a
    dec bc
    dec bc
    ld a, [bc]
    inc c
    dec c
    dec e
    inc l
    inc e
    dec e
    dec c
    inc l
    inc e
    dec c
    dec e
    dec sp
    inc a
    dec e
    dec c
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    add hl, hl
    ld a, [hl+]
    inc b
    inc b
    add hl, sp
    ld a, [hl-]
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    dec c
    dec e
    ld c, b
    ld c, c
    dec e
    dec c
    ld e, b
    ld e, c
    dec c
    dec e
    ld b, [hl]
    ld b, a
    dec e
    dec c
    ld d, [hl]
    ld d, a
    dec c
    dec e
    ld d, [hl]
    ld d, a
    dec e
    dec c
    ld d, [hl]
    ld d, a
    ld [bc], a
    inc bc
    db $10
    db $10
    add hl, bc
    ld a, [bc]
    ld a, [bc]
    inc c
    add hl, de
    ld a, [de]
    inc l
    inc e
    dec bc
    dec bc
    dec bc
    dec bc
    db $10
    db $10
    ld [bc], a
    inc bc
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec c
    dec e
    ld b, [hl]
    ld b, a
    dec e
    dec c
    ld d, [hl]
    ld d, a
    dec c
    dec e
    ld d, [hl]
    ld d, a
    dec e
    dec c
    dec sp
    inc a
    dec c
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    dec d
    ld bc, $0101
    dec d
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0d01
    dec e
    dec c
    dec e
    dec e
    dec c
    dec e
    dec c
    rlca
    ld [$1d0d], sp
    rla
    jr jr_01b_6d0c

    dec c
    ld c, $0f
    ld [bc], a
    inc bc
    ld e, $1f
    ld [de], a
    inc de
    dec c
    dec e
    ld b, [hl]
    ld b, a
    dec e
    dec c
    ld d, [hl]
    ld d, a
    db $10
    db $10
    db $10
    db $10
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec c
    dec e
    dec c
    dec e

jr_01b_6d0c:
    dec e
    dec c
    dec e
    dec c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor d
    nop
    ld d, l
    nop
    ld a, a
    ld a, a
    add b
    rst $38
    add b
    add b
    and b
    sbc a
    and b
    sub b
    and b
    sub b
    and b
    sub b
    and b
    sub b
    cp $fe
    ld bc, $00ff
    nop
    ld h, a
    sbc b
    ld b, e
    and h
    ld bc, $00c2
    add c
    ld bc, $01c2
    ld bc, $fefe
    inc b
    inc b
    cp $08
    pop af
    db $10
    db $f4
    inc e
    rst $30
    rra
    rst $30
    rra
    add b
    add b
    ld a, [hl]
    ld a, [hl]
    add hl, de
    add hl, de
    dec b
    rlca
    adc a
    inc bc
    ld a, a
    inc bc
    cpl
    inc de
    rst $28
    db $d3
    add b
    rst $38
    rst $38
    rst $38
    and b
    rst $38
    and l
    ld a, [$f7af]
    add sp, -$08
    ld e, c
    xor b
    xor c
    ld e, b
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    rst $38
    cp $01
    ld bc, $01f9
    ld sp, hl
    ld bc, $ff28
    add sp, -$01
    cpl
    rst $38
    xor b
    ld a, a
    ld l, b
    cp a
    cp a
    ld a, a
    ld d, l
    xor d
    xor d
    ld d, l
    dec b
    rst $38
    dec b
    rst $38
    db $fd
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
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
    ld bc, $aaff
    ld d, l
    ld a, [hl+]
    ld d, l
    xor d
    ld d, l
    ld d, l
    ld a, [hl+]
    sub h
    ld a, [hl+]
    ld d, l
    ld a, [hl+]
    xor d
    ld d, h
    add hl, hl
    ld d, h
    inc d
    ld a, [hl+]
    inc d
    ld a, [hl+]
    inc d
    ld a, [hl+]
    ld [$0814], sp
    inc d
    ld [$1414], sp
    ld a, [hl+]
    inc d
    ld a, [hl+]
    nop
    nop
    nop
    nop
    rra
    rra
    jr nz, jr_01b_6e18

    daa
    jr nz, jr_01b_6e22

    jr nz, jr_01b_6e24

    jr nz, jr_01b_6e1f

    jr nz, jr_01b_6e01

jr_01b_6e01:
    nop
    nop
    nop
    ld hl, sp-$08
    inc b
    inc b
    db $e4
    inc b
    db $e4
    inc b
    db $e4
    inc b
    inc b
    inc b
    nop
    nop
    rst $38
    rst $38
    add b
    add b
    add e
    cp a

jr_01b_6e18:
    add a
    cp h
    adc h
    cp b
    adc b
    cp b
    adc b

jr_01b_6e1f:
    cp [hl]
    nop
    nop

jr_01b_6e22:
    rst $38
    rst $38

jr_01b_6e24:
    ld bc, $c101
    db $fd
    pop hl
    dec a
    ld sp, $111d
    dec e
    ld de, $af7d
    sbc a
    cp b
    adc b
    cp h
    adc e
    cp b
    adc h
    cp h
    adc e
    cp a
    adc a
    cp a
    add b
    rst $38
    rst $38
    rst $38
    rst $38
    inc bc
    ld bc, $55ab
    ld bc, $a9ab
    ld d, a
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    ld [hl], a
    cp a
    di
    rst $18
    ld [hl], b
    sbc a
    ld a, h
    adc a
    ld a, a
    add e
    ld a, a
    add b
    rst $38
    nop
    rst $38
    rst $38
    ld l, a
    ld d, e
    rst $28
    db $d3
    db $ed
    rst $10
    add hl, hl
    rst $18
    dec a
    db $d3
    db $fd
    db $e3
    db $fd
    inc bc
    rst $38
    rst $38
    add hl, bc
    ld [$0808], sp
    rrca
    ld [$0b0f], sp
    ld c, $0b
    rrca
    dec bc
    rrca
    ld a, [bc]
    rrca
    rrca
    ld sp, hl
    ld bc, $0101
    rst $38
    ld bc, $fdff
    rlca
    db $fd
    rst $38
    db $fd
    rst $38
    dec b
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
    rst $38
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
    rst $38
    add b
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
    db $fc
    ld bc, $01fc
    db $fc
    ld bc, $01fc
    db $fc
    ld bc, $01fc
    db $fc
    ld bc, $01fc
    ccf
    jr nz, jr_01b_6f32

    cpl
    jr c, jr_01b_6f25

    ccf
    cpl
    ccf
    jr z, jr_01b_6f3a

    ccf
    nop
    nop
    nop
    nop
    db $fc
    inc b
    db $fc
    db $f4
    inc e
    db $f4
    db $fc
    db $f4
    db $fc
    inc d
    db $fc
    db $fc
    nop
    nop
    nop
    nop
    adc b
    cp b
    add l
    cp h
    add c
    cp a
    add b
    add b
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld de, $a11d
    dec a
    add c

jr_01b_6f25:
    db $fd
    ld bc, $ff01
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38

jr_01b_6f32:
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38

jr_01b_6f3a:
    nop
    rst $38
    nop
    rst $38
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
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    rst $38
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
    xor b
    ld bc, $0154
    xor b
    ld bc, $0154
    xor b
    ld bc, $0154
    xor b
    ld bc, $0154
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    cp a
    rst $38
    cp a
    pop bc
    cp a
    pop bc
    cp a
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
    cp $20
    jr nz, jr_01b_702b

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
    inc b
    inc b
    ld e, $1a
    ld l, e
    ld h, e
    pop af
    and l
    ld b, [hl]
    xor [hl]
    sbc a
    pop af
    or $ce
    sbc b
    ld hl, sp+$03
    ld bc, $0000
    ld [bc], a
    inc bc
    rrca
    ld c, $14
    ld e, $0e
    dec c
    inc a
    ld l, $3e

jr_01b_6fff:
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
    rst $38
    rst $38
    ld e, $12
    cp a
    dec l
    ld a, a
    dec l
    xor l
    inc sp
    ld [hl], e
    ccf
    cp a
    rra
    ld e, a
    ld c, $ff
    rst $38
    nop
    nop
    ld a, [c]
    ldh a, [$0d]
    ld hl, sp+$7a
    ldh a, [$f5]

jr_01b_702b:
    add b
    xor d
    nop
    ld d, l

jr_01b_702f:
    nop
    xor e
    inc bc
    ld e, l
    inc e
    cp [hl]
    ld l, b
    ld a, l
    jr nz, jr_01b_702f

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
    jr c, jr_01b_70a4

    jr z, jr_01b_6fff

    ld e, h
    ld b, l
    db $fc
    xor h
    ld a, [hl]
    ld d, a
    cp $7f
    rst $18
    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    rst $38
    ret nz

    ret nz

    cp $fb
    cp $03
    and $03
    and $03
    cp $03
    cp $03
    cp $ff
    inc bc
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
    nop
    nop
    nop
    rst $38
    inc a
    inc a
    ld h, [hl]
    ld h, [hl]
    ld b, d
    ld b, d
    ld b, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]

jr_01b_70a4:
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    ld e, d
    ld h, [hl]
    rst $38
    ld h, [hl]
    rst $38
    inc a
    ld a, [hl]
    nop
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
    rst $38
    nop
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    ld b, d
    rst $38
    cp l
    ld b, d
    ld b, d
    nop
    cp l
    ld b, d
    ld b, d
    rst $38
    rst $38
    rst $38
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
    rlca
    rra
    nop
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
    nop
    ldh [$7f], a
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
    jp nz, $b0ff

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
    ldh a, [rIE]
    rst $38
    add c
    rst $38
    add c
    rst $38
    push de
    xor e
    xor e
    push de
    push de
    xor e
    xor e
    push de
    rst $38
    add c
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
    ld d, l
    xor d
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    inc a
    jp $817e


    rst $38
    jp $bdff


    cp l
    add c
    add c
    add c
    add c
    rst $38
    ld a, [hl]
    nop
    rst $38
    nop
    add b
    nop
    cp h
    nop
    cp h
    nop
    add b
    ld a, $80
    nop
    add b
    nop
    rst $38
    ld l, a
    sub b
    ld b, a
    xor b
    inc bc
    call nz, $8201
    ld bc, $0382
    call nz, $a847
    ld l, a
    sub b
    add c
    add c
    add c
    add c
    push de
    add c
    xor e
    add c
    push de
    add c
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
    nop
    nop
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
    nop
    rst $38
    rst $38
    ld a, a
    rst $38
    ld a, a
    ret nz

    ld a, a
    rst $18
    ld [hl], b
    rst $18
    ld [hl], b
    rst $18
    ld [hl], b
    rst $18
    ld [hl], b
    rst $18
    ld [hl], b
    rst $18
    cp $ff
    cp $03
    cp $fb
    ld c, $fb
    ld c, $fb
    ld c, $fb
    ld c, $fb
    ld c, $fb
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
    nop
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
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    adc a
    ld hl, sp-$41
    adc b
    cp a
    adc b
    ld [hl], a
    ld hl, sp+$00
    nop
    rst $38
    rst $38
    ld bc, $ffff
    rst $38
    pop af
    rra
    rst $38
    ld de, $11ff
    xor $1f
    nop
    nop
    rst $38
    add c
    rst $38
    add c
    rst $38
    add c
    push de
    add c
    xor e
    add c
    push de
    add c
    add c
    add c
    add c
    add c
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
    rst $38
    nop
    nop
    nop
    nop
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
    add c
    xor e
    push de
    push de
    xor e
    xor e
    push de
    push de
    xor e
    add c
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld d, l
    xor d
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
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
    nop
    nop
    nop
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    ld b, b
    ld b, d
    ld b, b
    ld b, d
    ld a, [bc]
    dec bc
    ld a, [bc]
    dec bc
    ld a, [bc]
    dec bc
    ld a, [bc]
    dec bc
    ld a, [de]
    dec de
    ld a, [de]
    dec de
    ld [hl+], a
    ld [hl+], a
    db $10
    ld de, $2222
    jr nz, @+$23

    ld bc, $0126
    ld h, $26
    ld bc, $0126
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    jr nc, jr_01b_734b

    jr nc, jr_01b_734d

    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld b, b
    ld b, d
    ld [hl+], a
    ld [hl+], a
    jr z, jr_01b_7351

    jr nc, @+$33

    jr z, jr_01b_7355

    ld [hl+], a
    ld [hl+], a
    jr z, @+$2b

    ld b, b
    ld b, d
    ld b, b
    ld b, d
    jr z, @+$2b

    jr z, jr_01b_7361

    jr z, jr_01b_7363

    jr z, jr_01b_7365

    jr z, jr_01b_7367

    jr z, @+$2b

    ld bc, $0126
    ld h, $26
    ld bc, $0126
    ld bc, $0126

jr_01b_734b:
    ld h, $26

jr_01b_734d:
    ld bc, $0126
    ld [bc], a

jr_01b_7351:
    inc bc
    inc b
    dec b
    ld [de], a

jr_01b_7355:
    inc de
    inc d
    dec d
    ld b, $07
    ld [$1609], sp
    rla
    ld h, $01
    inc l

jr_01b_7361:
    dec l
    ld [hl+], a

jr_01b_7363:
    ld [hl+], a
    inc a

jr_01b_7365:
    dec a
    ld [hl+], a

jr_01b_7367:
    ld [hl+], a
    ld l, $2f
    ld bc, $3e26
    ccf
    ld h, $01
    ld [hl+], a
    ld [hl+], a
    inc l
    dec l
    ld [hl+], a
    ld [hl+], a
    inc a
    dec a
    ld bc, $2e26
    cpl
    ld h, $01
    ld a, $3f
    inc c
    dec c
    inc c
    dec c
    inc c
    dec c
    inc c
    dec c
    inc c
    dec c
    inc c
    dec c
    inc c
    dec c
    inc c
    dec c
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    daa
    daa
    daa
    daa
    scf
    scf
    scf
    scf
    inc l
    dec l
    ld bc, $3c26
    dec a
    ld h, $01
    ld l, $2f
    ld bc, $3e26
    ccf
    ld h, $01
    ld bc, $2c26
    dec l
    ld h, $01
    inc a
    dec a
    ld bc, $2e26
    cpl
    ld h, $01
    ld a, $3f
    ld b, b
    ld b, c
    ld b, c
    ld b, d
    ld d, b
    ld d, c
    ld d, c
    ld d, d
    ld d, b
    ld c, b
    ld c, c
    ld d, d
    ld d, e
    ld a, [hl-]
    ld a, [hl-]
    ld d, h
    ld bc, $0e26
    rrca
    ld h, $01
    ld e, $1f
    ld bc, $4026
    ld b, c
    ld h, $01
    ld d, b
    ld d, c
    ld bc, $0e26
    rrca
    ld h, $01
    ld e, $1f
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld d, c
    ld d, c
    ld d, c
    ld d, d
    ld b, l
    ld b, l
    ld b, [hl]
    ld b, l
    ld d, l
    ld d, l
    ld d, [hl]
    ld d, l
    ld a, [bc]
    dec bc
    ld c, e
    ld a, [bc]
    ld a, [de]
    dec de
    ld e, e
    ld a, [de]
    ld b, l
    ld b, [hl]
    ld b, l
    ld b, l
    ld d, l
    ld d, [hl]
    ld d, l
    ld d, l
    dec bc
    ld c, e
    ld a, [bc]
    dec bc
    dec de
    ld e, e
    ld a, [de]
    dec de
    ld bc, $5026
    ld d, c
    ld h, $01
    ld d, e
    ld a, [hl-]
    ld bc, $0e26
    rrca
    ld h, $01
    ld e, $1f
    ld d, c
    ld d, c
    ld d, c
    ld d, d
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld d, h
    ld bc, $0e26
    rrca
    ld h, $01
    ld e, $1f
    ld b, l
    ld b, [hl]
    ld b, l
    dec sp
    ld d, l
    ld d, [hl]
    ld d, l
    dec sp
    ld c, d
    ld c, e
    ld c, d
    dec sp
    ld e, d
    ld e, e
    ld e, d
    dec sp
    ld [hl], $36
    ld [hl], $36
    ld [hl], $36
    ld [hl], $36
    ld [hl], $36
    ld [hl], $36
    ld [hl], $36
    ld [hl], $36
    ld c, h
    ld c, l
    jr jr_01b_746d

    inc [hl]
    dec [hl]
    ld [hl+], a
    ld [hl+], a
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    inc hl
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    inc hl
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld bc, $0126
    ld h, $26

jr_01b_746d:
    ld bc, $0126
    inc e
    ld d, c
    ld d, c
    ld d, c
    inc e
    ld d, c
    ld d, c
    ld d, c
    inc e
    ld d, c
    ld d, c
    ld d, c
    inc e
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    dec e
    ld d, c
    ld d, c
    ld d, c
    dec e
    ld d, c
    ld d, c
    ld d, c
    dec e
    ld d, c
    ld d, c
    ld d, c
    dec e
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld bc, $3226
    inc sp
    ld h, $01
    ld b, e
    ld b, h
    ld bc, $3226
    inc sp
    ld h, $01
    ld b, e
    ld b, h
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld b, e
    ld b, h
    ld b, e
    ld b, h
    ld bc, $3226
    inc sp
    ld h, $01
    ld b, e
    ld b, h
    jr c, jr_01b_74fa

    ld bc, $3926
    add hl, sp
    ld h, $01
    jr c, @+$3a

    ld bc, $3926
    add hl, sp
    ld h, $01
    ld d, a
    ld e, b
    ld e, b
    ld e, c
    inc e
    ld b, a
    ld b, a
    dec e
    inc h
    jr jr_01b_74f4

    dec h
    ld a, [hl+]
    ld [hl+], a
    ld [hl+], a
    dec hl
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_74f4:
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_74fa:
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    jr c, jr_01b_7542

    ld bc, $3926
    add hl, sp
    ld h, $01
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    ld bc, $4026
    ld b, c
    ld h, $01
    ld a, [hl+]
    ld [hl+], a
    jr c, jr_01b_755a

    jr c, @+$3a

    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    jr c, jr_01b_756a

    jr c, @+$3a

    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    jr c, jr_01b_757a

jr_01b_7542:
    ld bc, $3926
    add hl, sp
    ld h, $01
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    dec hl
    ld [bc], a
    inc bc
    inc b
    dec b
    ld [de], a
    inc de
    inc d
    dec d
    ld b, $07

jr_01b_755a:
    ld [$1609], sp
    rla
    ld h, $01
    ld b, b
    ld b, c
    ld b, c
    ld b, d
    ld d, b
    ld c, b
    ld c, c
    ld d, d
    ld b, $07

jr_01b_756a:
    ld [$1609], sp
    rla
    ld h, $01
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_757a:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    ld [hl+], a
    ld d, a
    ld e, b
    ld [hl+], a
    ld [hl+], a
    inc e
    ld d, c
    ld bc, $1c26
    ld d, c
    ld h, $01
    inc e
    ld d, c
    ld e, b
    ld e, b
    ld e, b
    ld e, b
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld e, b
    ld e, b
    ld e, b
    ld e, b
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld e, b
    ld e, c
    ld [hl+], a
    ld [hl+], a
    ld d, c
    dec e
    ld [hl+], a
    ld [hl+], a
    ld d, c
    dec e
    ld bc, $5126
    dec e
    ld h, $01
    ld bc, $1c26
    ld d, c
    ld h, $01
    inc h
    ld c, [hl]
    ld bc, $2426
    ld c, [hl]
    ld h, $01
    ld a, [hl+]
    ld [hl+], a
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    ld c, [hl]
    jr jr_01b_7615

    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld d, c
    dec e
    ld bc, $4e26
    dec h
    ld h, $01
    ld c, [hl]
    dec h
    ld bc, $2226
    dec hl
    ld h, $01
    ld bc, $0126
    ld h, $26

jr_01b_7615:
    ld bc, $0126
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    dec hl
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld c, $0f
    ld bc, $1e26
    rra
    ld h, $01
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    ld b, b
    ld b, c
    ld b, c
    ld b, c
    ld a, [hl+]
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld bc, $0126
    ld h, $26
    ld bc, $0126
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld bc, $4026
    ld b, c
    ld h, $01
    ld d, b
    ld d, c
    ld bc, $5026
    ld d, c
    ld h, $01
    ld d, e
    ld a, [hl-]
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld d, c

jr_01b_7665:
    ld d, c
    ld d, c
    ld d, d
    ld d, c
    ld d, c
    ld d, c
    ld d, d
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld d, h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    ld a, $e1
    ccf
    ld hl, $ffff
    ccf
    db $eb
    ld hl, $21f5
    dec hl
    pop hl
    rst $28
    ld [hl], b
    sbc a
    ldh a, [$ef]
    ldh a, [$90]
    sbc a
    rst $28
    cp $f7
    ld de, $fff9
    rra
    ld e, $ff
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
    jr c, @+$01

    xor d
    nop
    ld a, a
    ccf
    cp a
    jr nz, jr_01b_7717

    jr nz, jr_01b_7665

    inc l
    ld h, l
    dec h
    and b
    jr nz, jr_01b_773e

    ccf
    rst $38
    cp $01
    ld bc, $03fd
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
    add d
    cp $38
    cp $45
    rst $00
    add e
    rst $00
    sub e
    rst $38
    cp $c7
    cp $fe
    cp b
    ld a, h
    nop
    nop
    nop
    rst $38
    ld d, l
    xor d
    nop

jr_01b_7717:
    nop
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    nop
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0301
    inc bc
    ld bc, $1f03
    ccf
    add b
    ret nz

    ld b, b
    ld b, b
    ld b, b
    ret nz

    adc [hl]
    adc [hl]
    rst $10
    pop de
    rst $30
    ld a, c
    xor c
    cp a

jr_01b_773e:
    cp [hl]
    cp [hl]
    inc e
    inc e
    ld [de], a
    ld [de], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    ld [hl-], a
    jp nc, Jump_01b_52f2

    ld a, [c]
    ld d, d
    ld a, [c]
    jp nc, Jump_000_00f2

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr c, jr_01b_77dc

    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    rst $30
    ld [hl], e
    ld a, a
    rst $38
    db $e3
    db $e3
    pop bc
    pop bc
    ret


    db $eb
    ld h, e
    rst $38
    rst $38
    ld a, a
    inc e
    rst $38
    rst $20
    db $e4
    ld a, a
    sbc h
    pop hl
    and e
    xor c
    db $eb
    jp hl


    xor e
    ld a, a
    sbc h
    rst $38
    ld [$ff1c], sp
    rst $38
    cp $fe
    rst $38
    rst $00
    rst $00
    add e
    add e
    sub e
    rst $10
    add $ff
    rst $38
    cp $38
    rst $38
    nop
    nop
    ld hl, sp-$08
    ld hl, sp+$08
    ld [$4808], sp
    ld c, a
    ld l, b
    ld l, [hl]
    ld [$f80c], sp
    ld hl, sp+$27
    dec a
    daa
    inc a
    dec hl
    dec sp
    inc a
    scf
    ccf
    ccf
    ccf
    jr nz, jr_01b_780c

    jr nz, jr_01b_780e

    ccf
    jp nc, $d6f2

    ld a, [$f25e]
    ld a, h
    db $e4
    ld hl, sp-$08
    ldh [$38], a

jr_01b_77dc:
    ldh [$38], a
    ldh [$f8], a
    rst $38
    rst $38
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
    rst $38
    rst $38
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

jr_01b_780c:
    rst $38
    rst $38

jr_01b_780e:
    rst $38
    rst $38
    ld d, l
    xor d
    xor d
    ld d, l
    ld d, l
    xor d
    xor d
    ld d, l
    nop
    nop
    xor d
    ld d, l
    nop
    rst $38
    nop
    nop
    ld h, e
    ld e, a
    ld e, $7f
    and d
    db $e3
    push bc
    rst $20
    ret


    rst $38
    ld a, a
    db $e3
    ld a, a
    ld a, a
    dec e
    ld a, $64
    ld h, h
    ld e, $1e
    and c
    and c
    cp a
    xor e
    cp a
    xor e
    inc e
    sbc l
    ld [$ff1c], sp
    inc e
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ccf
    ccf
    jr nz, jr_01b_788b

    inc hl
    ccf
    inc a
    inc a
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
    rra
    rra
    jr nz, jr_01b_7894

    jr nz, jr_01b_7896

    jr nz, jr_01b_7898

    ccf
    jr nz, jr_01b_78ba

    cpl
    add hl, sp
    dec hl
    rst $38
    rst $28
    ld hl, sp-$08
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    db $fc
    inc b
    db $fc

jr_01b_788b:
    db $f4
    db $fc
    db $f4
    rst $38
    rst $30
    cp a
    xor a
    cp a
    xor a

jr_01b_7894:
    cp a
    and b

jr_01b_7896:
    and b
    cp a

jr_01b_7898:
    cp a
    and b
    and b
    cp a
    cp a
    rst $38
    ret nz

    ld [$f7fd], a
    rst $38
    rst $30
    db $fd
    rlca
    rst $30
    rst $38
    db $fd
    rlca
    dec b
    rst $38
    db $fd
    rst $38
    inc bc
    and a
    ret nc

    rst $28
    ret nz

    ld [$e0bf], a
    cp a
    rst $38
    ld d, e
    ld a, a

jr_01b_78ba:
    inc a
    inc a
    inc de
    db $10
    cpl
    jr nz, jr_01b_78c4

    rst $30
    inc bc
    rla

jr_01b_78c4:
    db $fd
    rlca
    db $fd
    rst $38
    jp z, Jump_000_3cff

    inc a
    ret z

    ld [$04f4], sp
    cpl
    jr nz, jr_01b_7902

    jr nz, @+$25

    jr nc, jr_01b_78e7

    inc e
    inc c
    rrca
    dec bc
    rrca
    dec bc
    ld [$0707], sp
    db $f4
    inc b
    db $f4
    inc b
    call nz, $080c

jr_01b_78e7:
    jr c, jr_01b_7919

    ldh a, [$d0]
    ldh a, [$d0]
    db $10
    ldh [$e0], a
    nop
    ret nz

    nop
    ldh [rP1], a
    ld [hl], b
    nop
    jr c, jr_01b_78f9

jr_01b_78f9:
    inc e
    nop
    ld c, $00
    rlca
    nop
    inc bc
    nop
    inc bc

jr_01b_7902:
    nop
    rlca
    nop
    ld c, $00
    inc e
    nop
    jr c, jr_01b_790b

jr_01b_790b:
    ld [hl], b
    nop
    ldh [rP1], a
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

jr_01b_7919:
    inc bc
    inc c
    inc c
    inc de
    db $10
    cpl
    jr nz, jr_01b_7921

jr_01b_7921:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    jr nc, jr_01b_795c

    ret z

    ld [$04f4], sp
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
    nop
    nop
    nop
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
    ret nz

    nop
    ret nz

    nop
    ret nz

    nop
    ret nz

    nop
    ret nz

    nop
    ret nz

jr_01b_795c:
    nop
    ret nz

    nop
    ret nz

    nop
    inc bc
    nop
    inc bc
    nop
    inc bc
    nop
    inc bc
    nop
    inc bc
    nop
    inc bc
    nop
    inc bc
    nop
    inc bc
    nop
    rst $38
    nop
    nop
    ld a, [hl]
    ld a, [hl]
    ld b, d
    ld b, d
    ld b, d
    ld b, d
    ld b, b
    ld b, d
    ld [hl], a
    ld a, a
    ld d, h
    ld e, h
    nop
    rst $38
    nop
    nop
    add b
    add b
    db $fc
    call nc, $8082
    ld [bc], a
    ld [bc], a
    ld [$2ce8], a
    inc l
    ld [hl], h
    ld a, h
    ld [hl], h
    ld a, h
    rlca
    rlca
    dec b
    dec b
    rlca
    rlca
    rlca
    rlca
    nop
    nop
    nop
    rst $38
    jr z, jr_01b_79ca

    jr nz, jr_01b_79c4

    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$c0], a
    nop
    nop
    nop
    rst $38
    add c
    jp $c381


    add c
    jp $c381


    add c
    jp $c381


    add c
    jp $c381


    ld b, d
    ld b, d
    inc a
    inc a

jr_01b_79c4:
    nop
    nop
    nop
    nop
    nop
    nop

jr_01b_79ca:
    nop
    nop
    nop
    nop
    nop
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
    add c
    db $e3
    add b
    cp a
    cp a
    cp a
    rst $38
    ret nz

    ret nz

    cp a
    rst $38
    ld a, a
    ld d, l
    xor e
    xor e
    ld d, l
    pop bc
    cp a
    add c
    rst $38
    add c
    ld a, a
    ld bc, $01ff
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    add e
    db $fd
    add c
    rst $38
    add c
    cp $80
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    add c
    rst $00
    ld bc, $fdfd
    db $fd
    rst $38
    inc bc
    inc bc
    db $fd
    rst $38
    cp $aa
    push de
    push de
    xor d
    cp a
    ccf
    ld b, c
    ld l, e
    add e
    cp a
    add e
    db $eb
    add e
    cp a
    add e
    xor e
    add e
    cp a
    add e
    and e
    sub [hl]
    sub d
    rrca
    adc c
    add hl, de
    rra
    ld de, $211f
    ccf
    ld hl, $613f
    ld e, a
    ld b, c
    ld a, a
    ld l, c
    ld c, c
    ldh a, [$91]
    sbc b
    ld hl, sp-$78
    ld hl, sp-$7c
    db $fc
    add h
    db $fc
    add [hl]
    ld a, [$fe82]
    cp $fc
    add e
    sub $c1
    db $fd
    pop bc
    rst $10
    pop bc
    db $fd
    pop bc
    push de
    pop bc
    db $fd
    pop bc
    push bc
    rst $38
    ld a, a
    ret nz

    ld b, b
    ldh [$5f], a
    ld b, b
    rst $18
    ret nz

    ld e, a
    ret nz

    ld e, a
    ret nz

    ld e, a
    ld b, b
    rst $18
    rrca
    rrca
    dec de
    dec de
    ld [hl], $32
    scf
    ld sp, $7177
    ld d, a
    ld [hl], c
    rst $10
    pop de
    sub a
    db $d3
    ldh a, [$f0]
    ret c

    ret c

    ld l, h
    ld c, h
    db $ec
    adc h
    xor $8e
    ld [$eb8e], a
    adc e
    jp hl


    set 0, b
    ld e, a
    ret nz

    ld e, a
    ret nz

    ld e, a
    ld b, b
    rst $18
    ret nz

    ld e, a
    ret nz

    ld b, b
    rst $38
    ld a, a
    nop
    rst $38
    ld a, $80
    nop
    add b
    nop
    add b
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
    nop
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    add b
    nop
    and b
    nop
    xor d
    nop
    add b
    rst $38
    cp $03
    ld [bc], a
    rlca
    ld a, [$fb02]
    inc bc
    ld a, [$fa03]
    inc bc
    ld a, [$fb02]
    inc bc
    ld a, [$fa03]
    inc bc
    ld a, [$fb02]
    inc bc
    ld a, [$0203]
    rst $38
    cp $00
    rst $38
    rst $38
    ld a, a
    sbc a
    adc a
    or b
    sub l
    or b
    sbc a
    or b
    sub l
    cp a
    sbc a
    xor a
    sbc a
    or b
    adc a
    rst $38
    rst $38
    ret nz

    ret nz

    ccf
    jr nz, jr_01b_7b36

    jr nz, jr_01b_7b38

    jr nz, @+$01

    ldh [$df], a
    ldh [$3f], a
    ret nz

    rst $38
    rst $38
    inc bc
    inc bc
    db $fc
    inc b
    db $fc
    inc b
    db $fc
    inc b
    rst $38
    rlca
    ei
    rlca
    db $fc
    inc bc
    rst $38
    cp $f9
    pop af
    dec c
    xor e
    dec c
    ei
    dec c
    xor e
    db $fd
    ei
    push af
    ei
    dec c
    di
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rrca
    rra
    rrca
    rra
    rra
    rrca

jr_01b_7b36:
    rra
    rrca

jr_01b_7b38:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    inc bc
    ld b, $06
    ld b, $13
    ld b, $07
    ld [$1f0f], sp
    rlca
    ld [$0f1f], sp
    rlca
    ld [$0606], sp
    ld b, $06
    ld b, $06
    ld b, $06
    rrca
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    ld b, $01
    ld [bc], a
    inc bc
    ld b, $11
    ld [de], a
    inc de
    dec bc
    inc c
    ld c, $1f
    dec de
    inc e
    add hl, bc
    rrca
    ld b, $06
    ld bc, $0602
    ld b, $11
    ld [de], a
    rrca
    dec bc
    inc c
    ld c, $1e
    dec de
    inc e
    add hl, bc
    rrca
    rra
    rlca
    ld [$0f1f], sp
    rlca
    ld [$1f0f], sp
    rlca
    ld [$0f1f], sp
    rla
    jr @+$11

    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    ld [hl], $10
    db $10
    dec b
    rla
    jr @+$19

    jr jr_01b_7bb0

    dec bc
    inc c
    ld c, $1e
    dec de
    inc e
    add hl, bc
    rrca
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca

jr_01b_7bb0:
    dec e
    dec c
    rrca
    rra
    dec d
    ld d, $1f
    rrca
    rrca
    rra
    dec e
    dec c
    rra
    rrca
    dec d
    ld d, $0f
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    rrca
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    rrca
    dec bc
    inc c
    ld c, $1e
    dec de
    inc e
    add hl, bc
    rrca
    dec bc
    inc c
    ld c, $1e
    dec de
    inc e
    add hl, bc
    jr nz, jr_01b_7c03

    rrca
    rra
    ld [hl+], a
    inc hl
    rra
    rrca
    inc h
    dec h
    rrca
    rra
    ld h, $27
    rra
    rrca
    rrca
    rra
    jr nz, jr_01b_7c15

    rra
    rrca
    ld [hl+], a
    inc hl
    rrca
    rra
    inc h
    dec h
    rra
    rrca
    ld h, $27
    add hl, de
    add hl, de
    add hl, de

jr_01b_7c03:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    rrca
    rra
    rrca
    rra
    rra

jr_01b_7c15:
    rrca
    rra
    rrca
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    rrca
    rra
    rrca
    add hl, hl
    rra
    rrca
    add hl, hl
    add hl, hl
    rrca
    add hl, hl
    add hl, hl
    rrca
    add hl, hl
    add hl, hl
    rrca
    rrca
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    rrca
    rrca
    rrca
    rrca
    rrca
    ld b, b
    ld b, c
    rrca
    jr z, @+$11

    rrca
    rra
    jr z, @+$2a

    rra
    rrca
    rrca
    jr z, jr_01b_7c73

    rra
    rrca
    rrca
    jr z, jr_01b_7c78

    ld b, $30
    ld sp, $0606
    ld [hl-], a
    inc sp
    ld b, $0f
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    ld l, $2e
    ld a, [hl+]
    dec hl
    ld l, $2e
    ld h, $27
    jr z, jr_01b_7c92

    rrca
    rrca
    rra
    jr z, jr_01b_7c97

    rrca
    dec sp
    inc a
    dec a

jr_01b_7c73:
    ld a, $37
    jr c, jr_01b_7cb0

    ld a, [hl-]

jr_01b_7c78:
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld a, [hl+]
    dec hl
    cpl
    cpl
    ld h, $27
    cpl
    cpl
    rrca
    rrca
    add hl, hl
    add hl, hl
    rrca
    add hl, hl
    add hl, hl
    rrca
    ld b, $06

jr_01b_7c92:
    inc [hl]
    inc [hl]
    ld b, $06
    inc [hl]

jr_01b_7c97:
    inc [hl]
    rrca
    rra
    dec [hl]
    dec [hl]
    rra
    rrca
    rra
    rrca
    rrca
    rra
    jr z, jr_01b_7ccc

    rra
    rrca
    rra
    jr z, jr_01b_7cb8

    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca

jr_01b_7cb0:
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l

jr_01b_7cb8:
    rrca
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    add hl, hl
    add hl, hl
    rrca
    rra
    add hl, hl
    rrca
    rra
    rrca
    rrca
    rra
    rrca
    rra

jr_01b_7ccc:
    rra
    rrca
    rra
    rrca
    inc [hl]
    inc [hl]
    ld b, $06
    inc [hl]
    inc [hl]
    ld b, $06
    dec [hl]
    dec [hl]
    rrca
    rra
    rra
    rrca
    rra
    rrca
    ld b, a
    ld c, b
    ld c, c
    ld c, d
    rla
    jr jr_01b_7cfe

    jr jr_01b_7cf8

    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    add hl, hl
    inc l
    inc l
    jr z, jr_01b_7d21

    inc l
    inc l
    inc l

jr_01b_7cf8:
    rrca
    rrca
    rrca
    rrca
    rra
    rrca

jr_01b_7cfe:
    rrca
    rra
    ccf
    ld b, h
    ld b, h
    ld b, l
    ld b, d
    ld b, e
    ld b, e
    ld b, [hl]
    rrca
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca

jr_01b_7d21:
    rra
    rrca
    add hl, hl
    rra
    rrca
    rra
    jr z, jr_01b_7d38

    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    add hl, hl
    ld l, $2a
    dec hl
    jr z, jr_01b_7d64

    ld h, $27

jr_01b_7d38:
    jr z, jr_01b_7d62

    rrca
    rrca
    rra
    jr z, jr_01b_7d67

    rrca
    ld a, [hl+]
    dec hl
    cpl
    jr z, jr_01b_7d6b

    daa
    cpl
    add hl, hl
    rrca
    rrca
    add hl, hl
    add hl, hl
    rrca
    add hl, hl
    add hl, hl
    rrca
    jr z, jr_01b_7d71

    rrca
    rra
    add hl, hl
    rrca
    rra
    rrca
    rrca
    rra
    rrca
    rra
    rra
    rrca
    rra
    rrca
    nop
    nop

jr_01b_7d62:
    nop
    nop

jr_01b_7d64:
    nop
    nop
    nop

jr_01b_7d67:
    nop
    nop
    nop
    nop

jr_01b_7d6b:
    nop
    nop
    nop
    nop
    nop
    ld d, l

jr_01b_7d71:
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
    xor d
    ld d, l
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
    rst $38
    rst $38
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
    ld bc, $07ff
    rst $38
    dec e
    rst $38
    dec d
    rst $38
    rra
    rst $38
    rlca
    rst $38
    dec e
    rst $38
    ld [hl], l
    rst $38
    rst $18
    rst $38
    ld d, c
    rst $38
    pop af
    rst $38
    ld de, $17ff
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    cp a
    ret nz

    cp a
    ret nz

    cp a
    ret nz

    cp a
    rst $38
    cp a
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
    rst $38
    rst $38
    rst $38
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    rst $38
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    rst $38
    db $fd
    db $fd
    or a
    rst $38
    and l
    rst $20
    cp l
    push af
    cp a
    rst $18
    cp a
    ret nz

    cp a

jr_01b_7dec:
    ret nz

    cp a
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    cp a
    db $ed
    rst $38
    and l
    rst $20
    cp l

jr_01b_7e06:
    xor a
    db $fd
    ei
    db $fd
    inc bc
    db $fd
    inc bc
    db $fd
    rst $38
    cp $7f
    add b
    cp a
    ld b, b
    rst $18
    jr nz, jr_01b_7e06

    db $10
    rst $30
    ld [$04fb], sp
    db $fd
    ld [bc], a
    cp $01
    cp $01
    db $fd
    ld [bc], a
    ei
    inc b
    rst $30
    ld [$10ef], sp
    rst $18
    jr nz, jr_01b_7dec

    ld b, b
    ld a, a
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add b
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    rst $38
    rst $38
    ld bc, $fdff
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    ld de, $f1ff
    rst $38
    pop af
    rst $38
    rst $30
    rst $38
    db $fd
    rst $38
    push af
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    dec e
    rst $38
    ld [hl], l
    rst $38
    rst $18
    rst $38
    ld e, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld d, l
    xor e
    xor d
    ld d, a
    ld d, l
    xor [hl]
    xor d
    ld e, l
    ld d, l
    cp d
    xor d
    ld [hl], l
    ld d, l
    ld [$d5aa], a
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    rst $38
    cp a
    push de
    xor d
    ld [$7555], a
    xor d
    cp d
    ld d, l
    ld e, l
    xor d
    xor [hl]
    ld d, l
    ld d, a
    xor d
    xor e
    ld d, l
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
    ld b, $06
    ld b, $06
    add hl, bc
    add hl, bc
    add hl, bc
    add hl, bc
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
    jr jr_01b_7f47

    dec bc
    inc c
    dec d
    jr jr_01b_7f43

    dec bc
    jr jr_01b_7f4f

    dec bc
    inc c
    dec d
    jr jr_01b_7f4b

    dec bc
    dec bc
    inc c
    inc bc

jr_01b_7f43:
    inc b
    inc c
    dec bc
    inc de

jr_01b_7f47:
    inc d
    dec bc
    inc c
    dec bc

jr_01b_7f4b:
    inc c
    inc c
    dec bc
    inc c

jr_01b_7f4f:
    dec bc
    dec b
    ld b, $06
    ld b, $08
    add hl, bc
    add hl, bc
    add hl, bc
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
    ld b, $06
    ld b, $07
    add hl, bc
    add hl, bc
    add hl, bc
    ld a, [bc]
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
    jr jr_01b_7f8f

    dec bc
    inc c
    dec d
    jr jr_01b_7f8b

    dec bc
    ld b, $06
    ld b, $06
    add hl, bc
    add hl, bc
    add hl, bc
    add hl, bc
    jr jr_01b_7f9f

    dec bc

jr_01b_7f8b:
    inc c
    dec d
    jr jr_01b_7f9b

jr_01b_7f8f:
    dec bc
    ld de, $0202
    ld [bc], a
    rla
    db $10
    db $10
    db $10
    rla
    db $10
    db $10

jr_01b_7f9b:
    db $10
    rla
    db $10
    db $10

jr_01b_7f9f:
    db $10
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [de], a
    db $10
    db $10
    db $10
    ld d, $10
    db $10
    db $10
    ld d, $10
    db $10
    db $10
    ld d, $17
    db $10
    db $10
    db $10
    rla
    db $10
    db $10
    db $10
    rla
    db $10
    db $10
    db $10
    rla
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    ld d, $10
    db $10
    db $10
    ld d, $10
    db $10
    db $10
    ld d, $10
    db $10
    db $10
    ld d, $02
    ld [bc], a
    ld [bc], a
    ld [bc], a
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    jr jr_01b_7ff7

    dec bc
    inc c
    dec d
    jr jr_01b_7ff3

    dec bc
    inc bc
    inc b
    dec bc
    inc c
    inc de
    inc d
    inc c
    dec bc
    jr @+$17

    dec bc

jr_01b_7ff3:
    inc c
    dec d
    jr @+$0e

jr_01b_7ff7:
    dec bc
    dec bc
    inc c
    dec bc
    inc c
    inc c
    dec bc
    inc c
    dec bc
