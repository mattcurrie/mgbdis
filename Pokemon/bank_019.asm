; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $019", ROMX[$4000], BANK[$19]

    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    add hl, sp
    ld a, h
    xor d
    nop
    rst $18
    nop
    ld a, d
    add l
    push af
    ld a, [bc]
    ld a, [$bf05]
    ld b, b
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
    and d
    jr jr_019_4033

jr_019_4033:
    ld h, [hl]
    db $18, $81
    db $18, $81
    nop
    ld h, [hl]
    ld h, [hl]
    sbc c
    adc b
    ld [hl], a
    ld b, c
    jr jr_019_4041

jr_019_4041:
    rst $38
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0601
    rlca
    dec e
    ld a, [de]
    ld l, d
    ld [hl], l
    ld bc, $0601
    rlca
    inc e
    dec de
    ld l, d
    ld [hl], l
    call nc, $aaab
    ld d, l
    ld d, h
    xor e
    xor d
    ld d, l
    rst $38
    rst $38

jr_019_4072:
    nop
    nop

jr_019_4074:
    rst $38
    nop

jr_019_4076:
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
    add b
    add b
    ld h, b
    ldh [$58], a
    cp b
    ld l, $d6
    ld d, l
    xor e
    ld a, [hl+]
    push de
    ld d, l
    xor d
    ld a, [hl+]
    push de
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
    ldh [$60], a
    ld e, b
    cp b
    xor [hl]
    ld d, [hl]
    rst $38
    nop
    rst $38
    rst $38
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    rst $38
    add c
    rst $38
    rst $38
    ld e, a
    and b
    ld a, a
    cp a
    ld h, b
    cp a
    ld l, a
    cp a
    jr z, jr_019_4072

    jr z, jr_019_4074

    jr z, jr_019_4076

    cpl
    cp b
    ld a, [$fe05]
    db $fd
    ld b, $fd
    or $fd
    inc d
    dec e
    inc d
    dec e
    inc d
    dec e
    db $f4
    dec e
    nop
    nop
    ld bc, $4800
    nop
    nop
    nop
    nop
    nop
    add hl, bc
    nop
    nop
    nop
    ld b, b
    nop
    nop
    nop
    nop
    nop
    jr jr_019_40fe

    inc h
    inc h
    ld b, d
    ld b, d
    ld h, [hl]
    ld h, [hl]
    ld a, d
    ld e, [hl]
    ld [hl], d
    ld c, [hl]
    ld a, h
    inc b
    ld a, h
    inc b
    ld a, h
    inc b
    ld a, h
    inc b
    ld a, h
    inc b
    ld a, h
    inc b
    ld a, h
    inc b

jr_019_40fe:
    ld a, h
    inc b
    push hl
    ld l, $e5
    ld l, $e5
    ld l, $e5
    ld l, $e5
    ld l, $e5
    ld l, $e5
    ld l, $e5
    ld l, $eb
    nop
    sub [hl]
    ld b, c
    xor a
    nop
    rst $18
    nop
    ld a, d
    add l
    push af
    ld a, [bc]
    ld a, [$bf05]
    ld b, b
    ld a, [hl]
    add c
    cp l
    ld b, d
    db $db
    inc h
    rst $20
    jr @-$17

    jr @-$23

    inc h
    cp l
    ld b, d
    ld a, [hl]
    add c
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
    call c, $aad5
    xor d
    push de
    push de
    xor d
    xor d
    push de
    push de
    xor d
    xor d
    push de
    push de
    xor d
    xor d
    push de
    ld d, h
    xor e
    xor d
    ld d, l
    ld d, h
    xor e
    xor d
    ld d, l
    ld d, h
    xor e
    xor e
    ld d, l
    ld d, [hl]

jr_019_416d:
    xor a
    cp c

jr_019_416f:
    ld e, a
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

jr_019_417b:
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld d, l
    xor d
    ld a, [hl+]
    push de
    ld d, l
    xor d
    ld a, [hl+]
    push de
    ld d, l
    xor d
    xor d
    push de
    ld [hl], l
    ld [$fd9a], a
    ld d, l
    xor e
    xor e
    ld d, l
    ld d, l
    xor e
    xor e
    ld d, l
    ld d, l
    xor e
    xor e
    ld d, l
    ld d, l
    xor e
    xor e
    ld d, l
    rst $38
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
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    cpl
    cp a
    cpl
    or b
    jr z, jr_019_416d

    jr z, jr_019_416f

    cpl
    or b
    jr nz, jr_019_417b

    ccf
    cp a
    rst $38
    ret nz

    db $f4
    db $fd
    db $f4
    dec c
    inc d
    db $ed
    inc d
    db $ed
    db $f4
    dec c
    inc b
    db $fd
    db $fc
    db $fd
    rst $38
    inc bc
    xor d
    nop
    dec b
    ld d, b
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
    ld bc, $0301
    ld [bc], a
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
    ld a, $20
    ld a, $20
    ld a, $20
    ld a, $20
    ld a, $20
    ld a, $20
    ld a, $20
    ld a, $20
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    nop
    rst $38
    rst $00
    rst $38
    inc a
    rst $38
    rst $38
    nop
    rst $38
    inc a
    jp $8166


    jp $c381


    jp $e7a5


    db $db
    and $67
    rst $38
    inc a
    rst $38
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    push de
    xor d
    xor e
    push de
    sub $af
    cp c
    rst $18
    rst $20
    cp $9f
    ld hl, sp+$7f
    ld a, b
    ld [$6708], sp
    cp $9f
    ld hl, sp+$7f
    ldh [rIE], a
    add b
    ld hl, sp+$00
    ldh [rP1], a
    add b
    nop
    nop
    nop
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
    rst $20
    ld a, [hl]
    ld sp, hl
    rra
    cp $07
    rst $38
    ld bc, $001f
    rlca
    nop

jr_019_428c:
    ld bc, $0000
    nop
    ld d, l
    xor e
    xor e
    push de
    ld [hl], l
    db $eb

jr_019_4296:
    sbc e
    db $fd
    rst $20
    ld a, a
    ld sp, hl
    rra
    cp $1e
    db $10
    db $10
    rlca
    rlca
    rra
    jr jr_019_42dd

    jr nz, jr_019_4307

    ld b, b
    ld h, b
    ld b, b
    ld e, b
    ld b, b
    ld b, a
    ld b, b
    ld h, b
    ld b, b
    ret nz

    ret nz

    ldh a, [$30]
    jr c, @+$0a

    inc c
    inc b

jr_019_42b8:
    inc c
    inc b
    inc [hl]
    inc b
    call nz, $0c04
    inc b
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

jr_019_42dd:
    rst $38
    ld e, l
    ld a, a
    xor d
    jr z, jr_019_42b8

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
    rst $38
    nop
    nop
    nop
    ld a, d
    ld a, d
    jp nz, $dbc2

    db $db
    ret


    ret


    ld a, c
    ld a, c
    nop
    nop
    jr nz, jr_019_428c

    db $10
    dec b
    ld [$5000], sp

jr_019_4307:
    ld bc, $8a20
    inc b
    db $10
    jr nz, jr_019_4296

    nop
    ld d, c
    nop
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
    jp Jump_019_667e


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
    rst $38
    xor e

Call_019_4342:
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
    db $fc
    db $eb
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
    xor d
    ld d, l
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
    ld e, b
    ld h, b
    ld b, a
    ld a, b
    ld b, e
    ld a, h
    ld b, e
    ld a, h
    inc hl
    ld a, h
    dec de
    inc a
    rlca
    rra
    nop
    rlca
    inc [hl]
    inc c
    call nz, $843c
    ld a, h
    add h
    ld a, h
    adc b
    ld a, h
    or b
    ld a, b
    ret nz

    ldh a, [rP1]
    ret nz

jr_019_43c0:
    nop
    rst $38
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

jr_019_43cf:
    nop
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
    jr nc, jr_019_43c0

    jr c, jr_019_4455

    ld a, [c]
    sub l
    ldh [rIE], a
    nop
    nop
    nop
    ld d, c
    ld d, c
    ld e, e
    ld e, e
    rst $18
    rst $18
    sub l
    sub l
    sub l
    sub l
    nop

jr_019_43ff:
    nop
    xor e
    inc bc
    ld e, l
    inc e
    cp [hl]
    ld l, b
    ld a, l
    jr nz, jr_019_43ff

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
    jr c, jr_019_4474

    jr z, jr_019_43cf

    ld e, h
    ld b, l
    db $fc
    xor h
    ld a, [hl]
    ld d, a
    cp $ff
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
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    ld a, [hl+]
    ld a, [hl+]
    ld c, d
    ld c, d
    ld l, [hl]
    ld l, [hl]
    ld a, [hl+]
    ld a, [hl+]
    ld c, d
    ld c, d
    rst $38
    nop
    rst $38
    rst $38
    nop

jr_019_4455:
    nop
    ld h, [hl]
    ld h, [hl]
    xor d
    xor d
    xor [hl]
    xor [hl]
    xor b
    xor b
    ret z

    ret z

    nop
    nop
    inc a
    inc a
    ld a, a
    ld a, a
    add b
    rst $38
    add b
    add b
    add b
    sub d
    add b
    sbc d
    add b
    add b
    nop
    nop
    inc a
    inc a

jr_019_4474:
    cp $fe
    ld bc, $01ff
    ld bc, $d901
    ld bc, $01d1
    ld bc, $abd5
    ld b, h
    ld e, [hl]
    sbc a
    daa
    ld e, a
    cp a
    ccf
    ld e, a
    ld a, a
    cp a
    ccf
    rst $38
    rst $38
    rst $38
    push de
    xor e
    ld b, h
    ld e, [hl]
    ld hl, sp-$1b
    db $fd
    ld a, [$fbfc]
    db $fc
    rst $38
    rst $38
    rst $38
    rst $38
    db $fd
    nop
    nop
    nop
    ld a, [hl]
    nop
    nop
    rst $38
    rst $38
    inc h
    rst $20
    inc h
    rst $20
    rst $20
    rst $20
    rst $38
    inc a
    nop
    nop
    cp $00
    cp $00
    nop
    nop
    rst $28
    nop
    rst $28
    nop
    nop
    nop
    ld a, [hl]
    nop
    rrca

jr_019_44c1:
    rrca
    jr @+$1a

    jr @+$1a

    jr @+$1a

    rra
    jr jr_019_44e3

    jr jr_019_44e5

    jr jr_019_44e7

    jr jr_019_44c1

jr_019_44d1:
    ldh a, [rNR23]
    jr jr_019_44ed

    jr jr_019_44ef

    jr jr_019_44d1

    jr @+$1a

    jr @+$1a

    jr @+$1a

    jr @+$81

jr_019_44e1:
    inc b
    ld a, h

jr_019_44e3:
    inc b
    ld a, h

jr_019_44e5:
    inc b
    ld a, a

jr_019_44e7:
    inc b
    ld a, [hl]
    dec b
    ld a, [hl]
    dec b
    ld a, a

jr_019_44ed:
    inc bc
    ld a, a

jr_019_44ef:
    nop
    cp $20
    ld a, $20
    ld a, $20
    cp $20
    ld a, [hl]
    and b
    ld a, [hl]
    and b
    cp $c0
    cp $00
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
    ldh a, [rP1]
    nop
    nop
    ld b, h
    nop
    xor d
    ld l, h
    sub d
    inc [hl]
    ld c, d
    or l
    ld c, d
    db $d3
    inc l
    ld h, [hl]
    jr @+$01

    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    db $db
    inc h
    cp l
    ld b, d
    ld a, [hl]
    add c
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
    ld [hl], d
    ld c, [hl]
    ld [hl], d
    ld c, [hl]
    ld [hl], d
    ld c, [hl]
    ld [hl], d
    ld c, [hl]
    ld [hl], d
    ld c, [hl]
    inc [hl]
    ld l, [hl]
    jr jr_019_459a

    nop
    jr jr_019_44e1

    sbc d
    add b
    sbc d
    add b
    add b
    ld a, a
    ld a, a
    inc a
    inc h
    inc h
    rst $20
    jr @+$01

    nop
    nop
    ld bc, $0129
    xor c
    ld bc, $fe01
    cp $3c
    inc h
    inc h
    rst $20
    jr @+$01

    nop
    nop
    rst $38
    cp a
    ld a, a
    ld a, a
    cp a
    ccf
    ld a, a
    cp a
    ccf
    ld a, a
    ld a, d
    cp a
    dec [hl]
    rst $18
    ld a, [$fdcf]
    rst $38
    db $fc
    cp $fc
    db $fd
    db $fd
    cp $fc
    rst $38

jr_019_459a:
    xor h
    rst $38
    ld d, a
    ei
    xor a
    ld sp, hl
    jr jr_019_45ba

    jr @+$1a

    jr jr_019_45be

    jr @+$1a

    jr @+$1a

    jr @+$1a

    jr @+$1a

    jr @+$1a

    rst $38
    nop
    stop
    stop
    stop
    rst $38
    nop

jr_019_45ba:
    ld bc, $0100
    nop

jr_019_45be:
    ld bc, $1f00
    jr @+$1a

    jr @+$1a

    jr @+$1a

    jr jr_019_45e8

    jr jr_019_45ea

    rra
    rra
    db $10
    rra
    rra
    ld hl, sp+$18
    jr jr_019_45ec

    jr jr_019_45ee

    jr jr_019_45f0

    ld hl, sp+$18
    ld hl, sp-$08
    ld hl, sp+$08
    ld hl, sp-$08
    ld a, [bc]
    ld a, [bc]
    jr z, jr_019_460d

    ld c, e
    ld c, e
    ld c, e
    rra

jr_019_45e8:
    ld a, [bc]
    ld a, [bc]

jr_019_45ea:
    ld a, [bc]
    rra

jr_019_45ec:
    ld a, [de]
    ld a, [de]

jr_019_45ee:
    ld a, [de]
    ld c, a

jr_019_45f0:
    inc hl
    inc hl
    inc hl
    inc hl
    add hl, sp
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    add hl, sp
    inc hl
    dec b
    ld b, $07
    rlca
    dec d
    ld d, $17
    rla
    dec h
    ld h, $0b
    inc c
    ld c, [hl]

jr_019_460d:
    ld a, [de]
    dec de
    inc e
    rlca
    rlca
    ld [$1709], sp
    rla
    jr jr_019_4631

    ld a, [bc]
    ld a, [bc]
    jr z, @+$2b

    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld c, a
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
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc a

jr_019_4631:
    inc a
    inc a
    inc a
    inc b
    inc a
    inc b
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    ld de, $1111
    ld de, $1111
    ld de, $4811
    ld c, c
    scf
    scf
    ld e, b
    ld e, c
    scf
    scf
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    scf
    scf
    scf
    scf
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld b, [hl]
    ld b, a
    add hl, sp
    add hl, sp
    ld d, [hl]
    ld d, a
    rlca
    rlca
    rlca
    rlca
    rla
    rla
    rla
    rla
    inc hl
    ld a, [bc]
    ld a, [bc]
    inc hl
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    dec b
    ld b, $53
    ld d, e
    dec d
    jr c, jr_019_46b9

    ld [de], a
    dec d
    jr c, jr_019_46bd

    ld [de], a
    dec d
    ld d, $17
    rla
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a

jr_019_46b9:
    ld [de], a
    ld [de], a
    ld [de], a
    rla

jr_019_46bd:
    rla
    rla
    rla
    ld d, e
    ld d, e
    ld [$1209], sp
    ld [de], a
    jr c, jr_019_46e1

    ld [de], a
    ld [de], a
    jr c, jr_019_46e5

    rla
    rla
    jr jr_019_46e9

    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    dec h

jr_019_46e1:
    ld h, $0a
    ld a, [bc]
    rrca

jr_019_46e5:
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    rrca

jr_019_46e9:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, [hl]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld [hl+], a
    cpl
    ccf
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [bc]
    ld a, [bc]
    jr z, jr_019_472d

    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    rra
    dec bc
    inc c
    ld a, [bc]
    rra
    dec de
    inc e
    ld a, [de]
    ld c, a
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]

jr_019_472d:
    dec sp
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld [hl], $37
    scf
    scf
    ld c, $0e
    inc hl
    inc hl
    ld d, l
    ld d, l
    inc hl
    inc hl
    ld c, $0e
    inc hl
    inc hl
    ld d, l
    ld d, l
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    add hl, sp
    inc hl
    inc hl
    inc hl
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    inc sp
    inc sp
    inc sp
    inc sp
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    inc sp
    inc sp
    inc sp
    inc sp
    inc d
    inc d
    inc d
    ld d, h
    inc d
    inc d
    inc d
    ld d, h
    inc d
    inc d
    inc d
    ld d, h
    inc sp
    inc sp
    inc sp
    inc sp
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
    ld c, h
    ld d, e
    ld d, e
    ld d, e
    ld e, d
    ld [de], a
    ld [de], a
    ld [de], a
    ld e, d
    ld [de], a
    ld [de], a
    ld [de], a
    ld e, h
    rla
    rla
    rla
    ld d, e
    ld d, e
    ld d, e
    ld c, l
    ld [de], a
    ld [de], a
    ld [de], a
    ld e, d
    ld [de], a
    ld [de], a
    ld [de], a
    ld e, d
    rla
    rla
    rla
    ld e, l
    ld hl, $2323
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    ld hl, $2323
    db $10
    jr nz, @+$22

    jr nz, jr_019_4834

    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    jr nz, jr_019_483e

    jr nz, jr_019_4840

    daa
    daa
    ld de, $2711
    daa
    ld de, $2711
    ld [hl], $37
    scf
    ld [hl], $37
    scf
    scf
    ld de, $2411
    inc h

jr_019_4834:
    ld de, $2411
    inc h
    scf
    scf
    inc [hl]
    inc h
    scf
    scf

jr_019_483e:
    scf
    inc [hl]

jr_019_4840:
    db $10
    inc hl
    inc hl
    ld hl, $2310
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    ld hl, $2310
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    daa
    daa
    ld de, $2711
    daa
    ld de, $2711
    daa
    ld de, $2711
    daa
    ld de, $1111
    ld de, $2424
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    ld de, $1111
    ld de, $1111
    ld de, $3711
    inc de
    ld de, $1311
    daa
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    dec [hl]
    scf
    ld de, $2411
    dec [hl]
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1414
    inc d
    inc sp
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
    inc sp
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
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    scf
    inc [hl]
    inc a
    inc a
    dec b
    ld b, $07
    rlca
    dec d
    ld d, $17
    rla
    dec h
    ld h, $0a
    ld [hl+], a
    ld c, [hl]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld b, b
    ld b, c
    dec l
    ld l, $50
    ld d, c
    dec a
    ld a, $40
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    inc l
    inc l
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    inc l
    inc l
    dec l
    ld l, $2c
    inc l
    dec a
    ld a, $2d
    ld l, $2c
    inc l
    dec a
    ld a, $2c
    inc l
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    inc l
    inc l
    dec l
    ld l, $2c
    inc l
    dec a
    ld a, $40
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    inc l
    inc l
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    inc l
    inc l
    ld b, b
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    rrca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    ld c, e
    ld c, e
    ld c, e
    rrca
    ld c, e
    ld c, e
    ld c, e
    ld c, [hl]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    inc hl
    inc hl
    inc hl
    inc hl
    add hl, sp
    inc hl
    inc hl
    inc hl
    dec b
    ld b, $07
    rlca
    dec d
    ld d, $17
    rla
    inc hl
    inc hl
    inc hl
    inc hl
    add hl, sp
    inc hl
    inc hl
    inc hl
    rlca
    rlca
    ld [$1709], sp
    rla
    jr @+$1b

    ld a, [bc]
    ld c, e
    ld c, e
    ld a, [bc]
    ld c, e
    ld c, e
    ld c, e
    ld c, e
    dec bc
    inc c
    ld a, [bc]
    ld a, [bc]
    dec de
    inc e
    ld a, [de]
    ld a, [de]
    ld bc, $0201
    add hl, sp
    ld de, $2411
    ld [bc], a
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    dec h
    ld h, $0a
    ld [hl+], a
    ld e, h
    rla
    rla
    rla
    rrca
    ld [hl+], a
    dec bc
    inc c
    ld c, [hl]
    ld a, [de]
    dec de
    inc e
    ld a, [bc]
    ld a, [bc]
    jr z, jr_019_49dd

    rla
    rla
    rla
    ld e, l
    ld a, [bc]
    ld a, [bc]
    ld [hl+], a
    rra
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld c, a
    inc hl
    ld e, $01
    ld bc, $271e
    ld de, $2711
    daa
    ld de, $2711
    daa
    ld de, $0111
    ld bc, $0101
    ld de, $1111
    ld de, $1111
    ld de, $1111

jr_019_49dd:
    ld de, $1111
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    inc l
    inc l
    ld b, b
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    inc l
    inc l
    ld b, b
    ld b, c
    scf
    inc [hl]
    ld d, b
    ld d, c
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
    db $10
    inc hl
    inc hl
    ld hl, $2310
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    ld hl, $2020
    jr nz, jr_019_4a52

    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    jr nz, jr_019_4a5e

    jr nz, @+$23

    daa
    add hl, sp
    add hl, sp
    add hl, sp
    daa
    add hl, sp
    add hl, sp
    add hl, sp
    daa
    add hl, sp
    add hl, sp
    add hl, sp
    daa
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp

jr_019_4a52:
    dec c
    inc h
    add hl, sp
    add hl, sp
    dec c
    inc h
    add hl, sp
    add hl, sp
    dec c
    inc h
    add hl, sp
    add hl, sp

jr_019_4a5e:
    dec c
    inc h
    jr nz, jr_019_4a82

    jr nz, jr_019_4a85

    inc hl
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    ld hl, $2323
    db $10
    ld hl, $2020
    jr nz, jr_019_4a85

    inc hl
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    inc hl
    db $10
    inc hl
    inc hl
    ld hl, $3927

jr_019_4a82:
    add hl, sp
    add hl, sp
    daa

jr_019_4a85:
    add hl, sp
    add hl, sp
    add hl, sp
    daa
    add hl, sp
    add hl, sp
    add hl, sp
    ld [hl], $37
    inc a
    inc a
    add hl, sp
    add hl, sp
    dec c
    inc h
    add hl, sp
    add hl, sp
    dec c
    inc h
    add hl, sp
    add hl, sp
    dec c
    inc h
    ld [hl], $37
    scf
    inc [hl]
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
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
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
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
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld c, $0e
    ld b, [hl]
    ld b, a
    ld d, l
    ld d, l
    ld d, [hl]
    ld d, a
    ld de, $1111
    ld de, $1111
    ld de, $3711
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    daa
    inc l
    inc l
    inc l
    daa
    inc l
    inc l
    inc l
    daa
    inc l
    inc l
    inc l
    daa
    inc l
    inc l
    inc l
    inc l
    inc l
    dec e
    inc h
    inc l
    inc l
    dec e
    inc h
    inc l
    inc l
    dec e
    inc h
    inc l
    inc l
    dec e
    inc h
    daa
    inc l
    inc l
    inc l
    daa
    inc l
    inc l
    inc l
    daa
    inc l
    inc l
    inc l
    ld [hl], $37
    scf
    scf
    inc l
    inc l
    dec e
    inc h
    inc l
    inc l
    dec e
    inc h
    inc l
    inc l
    dec e
    inc h
    scf
    scf
    scf
    inc [hl]
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    inc a
    inc a
    ld [hl], $37
    ld hl, $2323
    ld hl, $2310
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    db $10
    inc hl
    inc hl
    db $10
    ld hl, $2323
    ld hl, $2323
    ld c, $0e
    inc hl
    inc hl
    ld d, l
    ld d, l
    inc hl
    inc hl
    ld c, $0e
    inc hl
    inc hl
    ld d, l
    ld d, l
    inc l
    inc l
    ld b, b
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    dec l
    ld l, $40
    ld b, c
    dec a
    ld a, $50
    ld d, c
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc l
    inc l
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld a, [hl-]
    dec sp
    inc d
    inc d
    inc d
    ld d, h
    inc d
    inc d
    inc d
    ld d, h
    inc d
    inc d
    inc d
    ld d, h
    inc d
    inc d
    inc d
    ld d, h
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    ld d, h
    ld [hl-], a
    inc d
    inc d
    ld d, h
    ld [hl-], a
    inc d
    inc d
    ld d, h
    ld [hl-], a
    inc d
    inc d
    ld d, h
    ld a, [hl+]
    dec hl
    inc sp

Call_019_4c53:
    inc sp
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    rrca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    ld c, e
    ld c, e
    ld c, e
    rrca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    ld c, e
    ld c, e
    ld c, e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rra
    ld c, e
    ld c, e
    ld c, e
    rra
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rra
    ld c, e
    ld c, e
    ld c, e
    rra
    inc sp
    inc sp
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc d
    inc d
    ld a, [hl-]
    dec sp
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld a, [hl-]
    dec sp
    ld a, [hl-]
    dec sp
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    ld b, b
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    inc l
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
    inc l
    ld b, b
    ld b, c
    inc l
    inc l
    ld d, b
    ld d, c
    inc l
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
    inc l
    inc l
    inc l
    inc l
    inc l
    ld b, b
    ld b, c
    ld b, b
    ld b, c
    ld d, b
    ld d, c
    ld d, b
    ld d, c
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    ld c, b
    ld c, c
    inc [hl]
    inc h
    ld e, b
    ld e, c
    scf
    inc [hl]
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    rla
    rla
    rla
    rla
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rra
    ld c, e
    ld c, e
    ld c, e
    rra
    ld b, d
    ld b, e
    ld c, e
    rra
    ld c, d
    ld c, d
    ld a, [de]
    ld c, a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rra
    ld c, e
    ld c, e
    ld c, e
    rra
    ld b, h
    ld b, l
    ld c, e
    rra
    ld c, d
    ld c, d
    ld a, [de]
    ld c, a
    inc l
    inc l
    inc l
    inc l
    inc l
    inc bc
    inc l
    inc bc
    inc bc
    inc l
    inc bc
    inc l
    inc l
    inc l
    inc l
    inc l
    dec d
    jr c, jr_019_4d45

    ld [de], a
    dec d
    jr c, jr_019_4d49

    ld [de], a
    dec d
    ld d, $17
    rla
    dec h
    ld h, $22
    ld [hl+], a
    ld [de], a
    ld [de], a
    jr c, jr_019_4d5d

    ld [de], a

jr_019_4d45:
    ld [de], a
    jr c, @+$1b

    rla

jr_019_4d49:
    rla
    jr @+$1b

    ld [hl+], a
    ld [hl+], a
    jr z, @+$2b

    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld c, $0e
    ld c, $0e
    ld d, l

jr_019_4d5d:
    ld d, l
    ld d, l
    ld d, l
    ld sp, $3131
    ld sp, $1414
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
    jr nc, jr_019_4da2

    jr nc, jr_019_4da4

    jr nc, jr_019_4da6

    jr nc, jr_019_4da8

    jr nc, jr_019_4daa

    ld b, [hl]
    ld b, a
    jr nc, jr_019_4dae

    ld d, [hl]
    ld d, a
    inc l
    jr nc, jr_019_4daf

    jr nc, jr_019_4db5

    inc l
    jr nc, jr_019_4db4

    inc l
    jr nc, jr_019_4db7

    jr nc, jr_019_4dbd

    inc l
    jr nc, jr_019_4dbc

    jr nc, jr_019_4dcb

    jr nc, jr_019_4dcd

    add hl, sp
    jr nc, jr_019_4dd0

    jr nc, jr_019_4dc9

    add hl, sp
    jr nc, jr_019_4dd5

    add hl, sp
    jr nc, jr_019_4dd8

    jr nc, jr_019_4db0

    ld a, [bc]

jr_019_4da2:
    ld a, [bc]
    ld a, [bc]

jr_019_4da4:
    rrca
    ld c, e

jr_019_4da6:
    ld c, e
    ld c, e

jr_019_4da8:
    rrca
    ld c, e

jr_019_4daa:
    dec bc
    inc c
    ld c, [hl]
    ld a, [de]

jr_019_4dae:
    dec de

jr_019_4daf:
    inc e

jr_019_4db0:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]

jr_019_4db4:
    ld c, e

jr_019_4db5:
    ld c, e
    ld c, e

jr_019_4db7:
    ld c, e
    ld c, e
    ld c, e
    ld c, e
    ld c, e

jr_019_4dbc:
    ld a, [de]

jr_019_4dbd:
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rra
    ld c, e
    ld c, e
    ld c, e
    rra
    ld c, e

jr_019_4dc9:
    ld c, e
    ld c, e

jr_019_4dcb:
    rra
    ld a, [de]

jr_019_4dcd:
    ld a, [de]
    ld a, [de]
    ld c, a

jr_019_4dd0:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, e

jr_019_4dd5:
    ld c, e
    ld c, e
    ld c, e

jr_019_4dd8:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, e
    ld c, e
    ld c, e
    ld c, e
    rst $38
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
    nop
    rst $38
    nop
    rst $38
    add b
    nop
    ld b, b
    nop
    jr nz, jr_019_4df6

jr_019_4df6:
    stop
    jr z, jr_019_4dfa

jr_019_4dfa:
    ld b, h
    nop
    add d
    nop
    ld bc, $8000
    nop
    ld b, b
    nop
    jr nz, jr_019_4e06

jr_019_4e06:
    stop
    jr z, jr_019_4e0a

jr_019_4e0a:
    ld e, a
    rra
    and b
    jr nz, jr_019_4e36

    jr nz, @-$7e

    nop
    ld b, b
    nop
    jr nz, jr_019_4e16

jr_019_4e16:
    stop
    jr z, jr_019_4e1a

jr_019_4e1a:
    db $fc
    ld hl, sp+$06
    inc b
    push hl
    inc b
    nop
    nop
    ld d, l
    xor d
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    ld h, b
    sbc a
    ld h, b
    sbc a
    nop
    rst $38
    rst $38
    rst $38
    add b
    add b
    add b
    add b

jr_019_4e36:
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    ccf
    ccf
    ld e, a
    ld b, b
    ld a, a
    ld a, a
    cp a
    add b
    cp a
    add b
    add b
    rst $38
    cp a
    rst $38
    cp [hl]
    pop hl
    db $fc
    db $fc
    cp $02
    cp $fe
    rst $38
    ld bc, $01ff
    ld bc, $fdff
    rst $38
    dec b
    rst $38
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
    sbc e
    ld [hl], l
    ld d, l
    ld hl, $de21
    ld h, [hl]
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


    xor $ea
    ld h, [hl]
    ld h, [hl]
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
    add b
    nop
    ld a, a
    ccf
    ld b, b
    ld h, b
    ld d, c
    ld l, [hl]
    ld e, a
    ld a, a
    ld b, b
    ld b, b
    adc $51
    ld b, b
    ld b, b
    add b
    nop
    ret nz

    add b
    ld h, b
    ret nz

    ld [hl], b
    ret nz

    ld l, b
    ret nz

    ld h, h
    ld b, b
    ld h, d
    ld b, b
    ld h, c
    ld b, b
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and a
    jr nz, jr_019_4f6a

    jr nz, @+$22

    jr nz, jr_019_4f46

    jr nz, jr_019_4f48

    cpl
    ld a, b
    cpl
    cp l
    ld a, [hl+]
    ld a, $39
    db $e4
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
    ld a, [hl]
    sub h
    db $fd
    inc e
    nop
    rst $38
    ld b, $f9
    ld b, $f9
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    ld d, l
    xor d
    nop
    nop
    rst $38
    rst $38
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rst $38
    rst $38
    or d
    pop hl
    cp [hl]
    pop hl
    and b
    rst $38

jr_019_4f46:
    and b
    rst $38

jr_019_4f48:
    and b
    rst $38
    cp a
    rst $38
    adc b
    rst $38
    ld a, a
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    db $fd
    rst $38

Jump_019_4f5c:
    ld de, $feff
    rst $38
    cpl
    scf
    daa
    jr c, @+$13

    inc e
    rla
    rra
    inc de
    inc e

jr_019_4f6a:
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
    ret nz

    ld a, a
    ld a, a
    ccf
    ccf
    db $10
    ld de, $2e11
    ld c, $44
    nop
    add d
    nop
    ld bc, $6c00
    call z, $92f2
    pop hl
    dec hl
    pop bc
    pop bc
    add a
    or [hl]
    adc [hl]
    cp b
    ld c, d
    ld c, b
    ld sp, $bf30
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
    ld bc, $bf01
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
    nop
    ld a, a
    rst $38
    ld a, b
    ret nc

    ld a, a
    rst $38
    ld hl, sp+$50
    ld a, a
    rst $38
    ld a, b
    ret nc

    ld a, a
    rst $38
    rst $38
    nop
    cp $ff
    ld c, $0b
    cp $ff
    rrca
    ld a, [bc]
    cp $ff
    ld c, $0b
    cp $ff
    ld a, a
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
    ld h, b
    sbc a
    sbc b
    rlca
    ld h, h
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
    inc bc
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
    ret nz

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
    cp a
    ld [$eaba], a
    xor d
    ld [$eaaf], a
    cp a
    ld a, [$ffbf]
    ld bc, $fdff
    rst $38
    db $fd
    sub a
    db $fd
    sub a
    sub l
    sub a
    sub l
    sub a
    db $fd
    rst $38
    db $fd
    rst $38
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

jr_019_5114:
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
    cp $f8
    ld d, b
    ld a, a
    rst $38
    ld a, b
    ret nc

    ld a, a
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    rrca
    ld a, [bc]
    cp $ff
    ld c, $0b
    cp $ff
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    cp a
    add b

jr_019_5142:
    cp a
    add b
    cp a
    add b

jr_019_5146:
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
    or $16
    ei
    dec de
    xor $27
    db $ed
    dec l
    ei
    jr jr_019_5146

    jr jr_019_5142

    inc e
    di
    rrca
    rlca
    ld h, h
    sbc a
    sbc b
    rst $30
    db $e4
    or a
    db $f4
    rst $18
    jr c, jr_019_5142

    jr c, jr_019_5114

    ld a, b
    rst $08
    ldh a, [$fd]
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

jr_019_51c4:
    inc bc
    ld bc, $0103

jr_019_51c8:
    inc bc
    ld bc, $0103
    inc bc
    ld bc, $0103
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
    rra
    jr nz, jr_019_51c4

    jr nz, @-$1e

    jr nz, jr_019_51c8

    rst $38
    jr nz, jr_019_522a

    rst $28
    ld sp, hl
    db $eb
    cp a
    xor a
    rst $38
    ld hl, sp+$04
    rlca
    inc b
    rlca
    inc b
    rlca
    rst $38
    inc b
    db $fc
    rst $30
    rst $38
    rst $30
    rst $38
    push af
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
    cp $20
    jr nz, jr_019_529b

    ld e, b
    ld a, [hl]
    ld h, [hl]
    rst $28
    sub l
    ld h, e
    ld a, l

jr_019_522a:
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
    ld hl, sp+$01
    ld bc, $0000
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
    nop
    nop
    nop
    nop
    nop
    nop
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
    xor e
    xor d
    xor e
    cp d
    cp e
    cp d
    cp e
    xor d
    xor e
    xor d
    xor e
    cp d
    cp e
    cp d
    cp e
    ld [bc], a
    inc bc
    ld h, $27
    ld [de], a
    inc de
    ld [hl], $37
    ld [bc], a
    inc bc
    inc l
    ld a, [hl+]
    ld [de], a
    inc de
    inc a
    ld a, [hl-]
    jr z, jr_019_52bb

    ld [bc], a
    inc bc
    jr c, @+$3b

    ld [de], a
    inc de
    ld a, [hl+]
    dec hl
    ld [bc], a

jr_019_529b:
    inc bc
    ld a, [hl-]
    dec sp
    ld [de], a
    inc de
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
    ld bc, $2601
    add hl, hl
    ld h, $29
    jr nc, jr_019_52e7

    jr nc, @+$33

    ld [hl+], a
    inc hl
    ld [hl+], a

jr_019_52bb:
    inc hl
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    nop
    nop
    inc h
    dec h
    nop
    nop
    inc [hl]
    dec [hl]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0f0e
    ld bc, $1e01
    rra
    ld bc, $0101
    ld bc, $0101
    ld bc, $0001
    nop
    inc h
    dec h
    nop
    nop
    inc [hl]

jr_019_52e7:
    dec [hl]
    ld bc, $0c01
    dec c
    ld bc, $1c01
    dec e
    nop
    nop
    inc h
    dec h
    nop
    nop
    inc [hl]
    dec [hl]
    ld bc, $0a01
    dec bc
    ld bc, $1a01
    dec de
    nop
    nop
    inc h
    dec h
    nop
    nop
    inc [hl]
    dec [hl]
    ld bc, $0601
    rlca
    ld bc, $1601
    rla
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
    ld bc, $0101
    ld bc, $0101
    ld bc, $0401
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    dec l
    ld l, $01
    ld bc, $3e3d
    ld bc, $3d01
    ld a, $01
    ld bc, $2f3f
    ld bc, $0101
    ld bc, $0706
    ld bc, $1601
    rla
    ld bc, $0e01
    rrca
    ld bc, $1e01
    rra
    ld [bc], a

jr_019_5351:
    inc bc
    ld bc, $1201
    inc de
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $4001
    ld b, c
    nop
    nop
    jr nz, @+$23

    ld h, $27
    ld b, d
    ld b, e
    inc l
    ld a, [hl+]
    ld [hl-], a
    inc sp
    inc a
    ld a, [hl-]
    nop
    nop
    nop
    nop
    daa
    add hl, hl
    nop
    nop
    ld a, [hl+]
    dec hl
    ld bc, $3a01
    dec sp
    ld bc, $4401
    ld b, l
    ld bc, $0801
    add hl, bc
    ld bc, $4601
    ld b, a
    ld bc, $1801
    add hl, de
    ld bc, $ff01
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
    nop
    rst $38
    nop
    rst $38
    add b
    nop
    ld b, b
    nop
    jr nz, jr_019_53b6

jr_019_53b6:
    stop
    jr z, jr_019_53ba

jr_019_53ba:
    ld b, h
    nop
    add d
    nop
    ld bc, $8000
    nop
    ld b, b
    nop
    jr nz, jr_019_53c6

jr_019_53c6:
    stop
    jr z, jr_019_53ca

jr_019_53ca:
    ld e, a
    rra
    and b
    jr nz, jr_019_53f6

    jr nz, jr_019_5351

    nop
    ld b, b
    nop
    jr nz, jr_019_53d6

jr_019_53d6:
    stop
    jr z, jr_019_53da

jr_019_53da:
    db $fc
    ld hl, sp+$06
    inc b
    push hl
    inc b
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    ldh a, [rIF]
    ldh a, [rIF]
    rrca
    ldh a, [rIF]
    ldh a, [rIE]
    rst $38
    add b
    add b
    add b
    add b

jr_019_53f6:
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    ccf
    ccf
    ld e, a
    ld b, b
    ld a, a
    ld a, a
    cp a
    add b
    cp a
    add b
    add b
    rst $38
    cp a
    rst $38
    cp [hl]
    pop hl
    db $fc
    db $fc
    cp $02
    cp $fe
    rst $38
    ld bc, $01ff
    ld bc, $fdff
    rst $38
    dec b
    rst $38
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
    sbc e
    ld [hl], l
    ld d, l
    ld hl, $de21
    ld h, [hl]
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


    xor $ea
    ld h, [hl]
    ld h, [hl]
    jr nz, jr_019_5462

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
    ld hl, sp+$3a
    daa

jr_019_5462:
    rla
    rra
    dec de
    rra
    ld a, e
    ld h, [hl]
    and l
    sbc e
    ei
    xor a
    ld a, a
    ld l, e
    dec d
    dec d
    adc [hl]
    cp $bf
    ld a, a
    rst $38
    jr jr_019_54a6

    rst $38
    rst $20
    ld e, a
    cp [hl]
    pop bc
    cp $ab
    ld e, l
    ld e, l
    ret nz

    add b
    rst $38
    cp a
    rst $38
    and h
    db $e4
    cp a
    db $e4
    and h
    rst $38
    cp a
    rst $38
    cp a
    ret nz

    add b
    inc bc
    ld bc, $fdff
    rst $38
    add l
    rst $38
    add l
    or a
    add l
    rst $08
    call $fdff
    inc bc
    ld bc, $ffff
    rst $38
    rst $38
    rst $38
    rst $38

jr_019_54a6:
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and a
    jr nz, jr_019_552a

    jr nz, jr_019_54e5

    jr nz, jr_019_5506

    jr nz, jr_019_5508

    cpl
    ld a, b
    cpl
    cp l
    ld a, [hl+]
    ld a, $39
    db $e4
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
    ld a, [hl]
    sub h
    db $fd
    inc e
    ldh a, [rIF]
    ldh a, [rIF]
    rrca

jr_019_54e5:
    ldh a, [rIF]
    ldh a, [rP1]
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rst $38
    rst $38
    or d
    pop hl
    cp [hl]
    pop hl
    and b
    rst $38

jr_019_5506:
    and b
    rst $38

jr_019_5508:
    and b
    rst $38
    cp a
    rst $38
    adc b
    rst $38
    ld a, a
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    dec b
    rst $38
    db $fd
    rst $38
    ld de, $feff
    rst $38
    cpl
    scf
    daa
    jr c, @+$13

    inc e
    rla
    rra
    inc de
    inc e

jr_019_552a:
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
    nop
    nop
    nop
    rlca
    rlca
    ld [$1308], sp
    db $10
    daa
    jr nz, jr_019_55bc

    ld b, b
    ld h, a
    ld b, b
    nop
    nop
    nop
    nop
    add b
    add b
    ld b, b
    ld b, b
    jr nz, jr_019_559a

    sub b
    db $10
    ret z

    ld [$04e4], sp
    rst $38
    cp a
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
    ret nz

    add b
    ld a, a
    ld a, a
    rst $38
    db $fd
    add e
    db $fd
    add e
    db $fd
    add e
    db $fd
    add e
    db $fd

jr_019_559a:
    rst $38
    rst $38
    inc bc
    ld bc, $fefe
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

jr_019_55bc:
    rst $38
    ld sp, hl
    ld bc, $3f01
    ccf
    ld b, c
    ld a, a
    ld b, c
    ld b, c
    ld b, c
    ld a, a
    ld b, c
    ld a, a
    ld b, c
    ld a, a
    ld b, c
    ld b, c
    ld a, a
    ld a, a

jr_019_55d0:
    rst $38
    jr nz, jr_019_55e3

    rst $38
    rrca
    rst $38
    jr jr_019_55d0

    ldh [rNR41], a
    jr nz, jr_019_55bc

    ld b, b
    ret nz

    ld b, b
    ret nz

    rst $38
    nop
    rst $38

jr_019_55e3:
    rst $38
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    add c
    add c

jr_019_55f0:
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    jr c, jr_019_55f0

    add h
    ld a, h
    jp nc, $d2be

    cp [hl]
    jp nc, Jump_019_7fbe

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
    add b
    jr jr_019_566b

    inc h
    nop
    jr jr_019_5627

jr_019_5627:
    ld [hl], b
    db $10
    adc h
    ld a, h
    add d
    sbc h
    ld h, d
    inc bc
    inc e
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
    ld [$1408], sp
    inc e
    inc d
    inc e
    ld l, [hl]
    ld a, d
    adc $ba
    ld h, l
    ld e, e
    ld [hl], a
    ld c, l
    ld [hl-], a
    dec a
    jr nz, jr_019_5672

    ld d, b
    ld [hl], b
    ld e, h
    ld a, h
    rst $38
    xor e
    rst $00
    cp c
    sbc $66
    adc h
    ld a, h
    ld [hl], $ca
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    dec bc
    ld [$1f17], sp
    rrca

jr_019_566b:
    rrca
    dec d
    dec de
    ld a, [de]
    dec d
    rst $38
    nop

jr_019_5672:
    ld a, a
    rst $38
    ld b, b
    ret nz

    ld b, b
    rst $18
    call z, Call_019_4c53
    db $d3
    ld b, b
    rst $18
    ld b, c
    sbc $ff
    nop
    cp $ff
    ld [bc], a
    inc bc
    ld [bc], a
    ei
    inc bc
    ld a, [$fb02]
    jp nz, $e23b

    dec de
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
    add b
    rst $38
    cp a
    rst $38
    cp a
    ld [$eaba], a
    xor d
    ld [$efaf], a
    cp a
    rst $38
    add b
    rst $38
    ld bc, $fdff
    rst $38
    db $fd
    sub a
    db $fd
    sub a
    sub l
    sub a
    sbc l
    sbc a
    db $fd
    rst $38
    ld bc, $11ff
    pop af
    pop af
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
    add c
    add c
    rst $38
    add c
    rst $38
    add c
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
    ldh a, [$e5]
    ld d, l
    xor e
    rst $38
    ccf
    rst $00
    rst $08
    dec bc
    ld [$e3e3], sp
    ld b, b
    ret nz

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
    nop
    stop
    ld e, d
    nop
    ld a, [hl]
    nop
    ld a, [hl]
    nop
    inc a
    nop
    inc a
    nop
    jr jr_019_571f

jr_019_571f:
    nop
    cp $92

jr_019_5722:
    jp c, $d292

    cp [hl]
    add h
    ld a, h
    jr c, jr_019_5722

    ret nz

    ret nz

    nop
    nop
    nop
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
    jp Jump_019_4f5c


    ret nc

    ld b, b
    rst $18
    ld b, b
    ret nz

    rst $38
    ld a, a
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    di
    ld a, [bc]
    ld a, [c]
    dec bc

jr_019_5784:
    ld [bc], a
    ei

jr_019_5786:
    ld [bc], a
    inc bc

jr_019_5788:
    rst $38
    cp $00
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    db $10
    rst $38
    db $10
    rst $38
    rst $38
    ld a, [hl+]
    inc b
    rst $38
    ld a, [bc]
    rst $38
    nop
    rst $38
    rst $38
    rra
    jr nz, jr_019_5784

    jr nz, jr_019_5786

    jr nz, jr_019_5788

    rst $38
    jr nz, jr_019_57ea

    rst $28
    ld sp, hl
    db $eb
    cp a
    xor a
    rst $38
    ld hl, sp+$04
    rlca
    inc b
    rlca
    inc b
    rlca
    rst $38
    inc b
    db $fc
    rst $30
    rst $38
    rst $30
    rst $38
    push af
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
    cp $73
    ld h, b
    ld a, c
    ld d, b
    ld a, h
    ld e, b
    ld a, $34
    rra
    ld [bc], a

jr_019_57ea:
    rrca
    inc bc
    rlca
    ld [bc], a
    inc bc
    ld bc, $04cc
    sbc h
    inc c
    inc a
    inc d
    ld a, h
    jr c, @-$06

    ld b, b
    ldh a, [$c0]
    ldh [rLCDC], a
    add b
    add b
    cp a
    add a
    cp h
    add a
    cp a
    add a
    cp a
    add b
    cp a
    sbc a
    and b
    and b
    xor [hl]
    and b
    and b
    and b
    rst $38
    ld hl, sp+$17
    db $e4
    rst $38
    ld hl, sp-$01
    nop
    rst $38
    ld a, h
    add e
    add d
    dec sp
    add d
    inc bc
    add d
    rst $38
    ld a, a
    ld b, b
    ret nz

    ld a, a
    rst $18
    ld e, a
    rst $18
    rst $18
    ld e, a
    ld e, a
    rst $18
    ld e, a
    rst $18
    ld e, a
    rst $18
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
    ld b, b
    ld b, b
    rst $38
    ldh a, [rIE]
    jr @+$21

    rlca
    inc b
    inc b
    rlca
    ld [bc], a
    inc bc
    inc bc
    inc bc
    rst $38
    cp $02
    inc bc
    cp $fb
    ld a, [$fbfb]
    ld a, [$fbfa]
    ld a, [$fafb]
    ei
    ldh [rIE], a
    ldh [rIE], a
    ldh [rIE], a

jr_019_5866:
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
    cp a
    add b
    sbc a
    ldh [$a3], a
    sbc h
    call nc, $ab83
    add b
    call nc, $e840
    jr nz, jr_019_5927

    ld d, b
    rst $38
    nop
    rst $38
    nop
    rst $18
    jr nz, jr_019_5866

    ld d, b
    ld d, a
    xor b
    ld a, e
    add h
    add hl, sp
    ld b, [hl]
    ld b, $7f
    ld hl, sp-$58
    cp a
    db $e4
    ld a, a
    ld b, e
    rra
    dec de
    daa
    dec h
    ld a, e
    ld b, [hl]
    ld b, a
    ld a, h
    jr c, jr_019_5908

    cp a
    ld a, a
    ld b, b
    rst $38
    cp a
    rst $38
    ld d, b
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    nop
    nop
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
    and b
    and b
    and b
    and b
    and b
    and b
    and b
    and b

jr_019_5908:
    cp a
    and b
    cp a
    sbc a
    cp a
    add b
    ret nz

    rst $38
    inc bc
    add d
    inc bc
    add d
    inc bc
    add d
    inc bc
    add d
    ld a, a
    add d
    rst $38
    db $fc
    rst $38
    nop
    nop
    rst $38
    rst $18
    ld e, a
    ld e, a
    rst $18
    ld e, a
    rst $18
    ld e, a

jr_019_5927:
    rst $18
    rst $18
    ld a, a
    ld b, b
    ret nz

    ld a, a
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    add c
    add c
    sbc c
    add c
    sbc c
    nop
    ld a, [hl]
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
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    ei
    ld a, [$fbfa]
    ld a, [$fafb]
    ei
    ei
    cp $02
    inc bc
    cp $ff
    nop
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
    xor d
    xor e
    xor d
    xor e
    cp d
    cp e
    cp d
    cp e
    xor d
    xor e
    xor d
    xor e
    cp d
    cp e
    cp d
    cp e
    ld bc, $0101
    ld bc, $0101
    ld bc, $0201
    inc bc
    ld h, $27
    ld [de], a
    inc de
    ld [hl], $2f
    ld bc, $0101
    ld bc, $0101
    ld bc, $2701
    add hl, hl
    ld [bc], a
    inc bc
    cpl
    add hl, sp
    ld [de], a
    inc de
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
    ld bc, $2601
    add hl, hl
    ld h, $29
    ld c, $0f
    ld c, $0f
    ld c, $0f
    ld c, $0f
    ld e, $1f
    ld e, $1f
    nop
    nop
    inc h
    inc h
    nop
    nop
    inc [hl]
    inc [hl]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0a01
    dec bc
    ld bc, $0801
    add hl, bc
    ld bc, $1a01
    dec de
    ld bc, $1801
    add hl, de
    ld bc, $0101
    ld bc, $0b0a
    ld bc, $0801
    add hl, bc
    ld bc, $1a01
    dec de
    ld bc, $1801
    add hl, de
    nop
    nop
    inc h
    inc h
    nop
    nop
    inc [hl]
    inc [hl]
    ld bc, $0101
    ld bc, $0101
    ld bc, $0001
    nop
    ld h, $29
    nop
    nop
    jr nc, @+$33

    ld bc, $3001
    ld sp, $0101
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
    ld bc, $0101
    ld bc, $0101
    ld bc, $0401
    inc b
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    ld [bc], a
    inc bc
    ld [hl], $2f
    ld [de], a
    inc de
    inc a
    ld a, [hl-]
    ld bc, $0101
    ld bc, $0101
    ld bc, $2f01
    add hl, sp
    ld [bc], a
    inc bc
    ld a, [hl-]
    dec sp
    ld [de], a
    inc de
    ld bc, $0101
    ld bc, $0101
    ld bc, $0001
    nop
    dec l
    ld l, $00
    nop
    dec a
    ld a, $01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $4001
    ld b, c
    nop
    nop
    jr nz, jr_019_5aa7

    ld h, $27
    ld b, d
    ld b, e
    ld [hl], $2f
    ld e, $1f
    inc a
    ld a, [hl-]
    nop
    nop
    nop
    nop
    daa
    add hl, hl
    nop
    nop
    cpl
    add hl, sp
    ld bc, $3a01
    dec sp
    ld bc, $0001
    nop
    ld c, b
    ld c, c
    nop
    nop
    ld e, b

jr_019_5aa7:
    ld e, c
    ld bc, $0101
    ld bc, $0101
    ld bc, $4901
    ld c, e
    nop
    nop
    ld e, d
    ld e, e
    nop
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld h, $27
    ld bc, $4601
    ld b, a
    ld bc, $0101
    ld bc, $0101
    ld bc, $2701
    add hl, hl
    ld bc, $2f01
    add hl, sp
    ld bc, $2401
    inc h
    nop
    nop
    inc [hl]
    inc [hl]
    nop
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0001
    ccf
    nop
    ccf
    ccf
    nop
    ccf
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $5756
    ld bc, $3c01
    ld a, [hl-]
    ld bc, $0201
    inc bc
    ld bc, $1201
    inc de
    cpl
    add hl, sp
    ld bc, $3a01
    dec sp
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $2926
    ld h, $29
    jr nc, @+$33

    jr nc, jr_019_5b59

    jr nc, jr_019_5b5b

    jr nc, jr_019_5b5d

    ld e, $1f
    ld e, $1f
    ld bc, $3701
    jr z, jr_019_5b36

    scf

jr_019_5b36:
    ld bc, $2801
    ld bc, $0137
    ld bc, $0137
    ld bc, $3701
    ld bc, $3701
    ld bc, $0128
    ld [bc], a
    inc bc
    ld h, $27
    ld [de], a
    inc de
    ld [hl], $2f
    ld bc, $0101
    ld bc, $0101
    ld bc, $2701

jr_019_5b59:
    add hl, hl
    inc e

jr_019_5b5b:
    dec e
    cpl

jr_019_5b5d:
    add hl, sp
    ld b, h
    ld b, l
    ld [hl+], a
    ld bc, $0128
    ld bc, $0122
    jr z, @+$03

    ld bc, $0101
    ld bc, $0101
    ld bc, $3f00
    inc hl
    ld c, d
    ccf
    nop
    ld d, h
    ld d, l
    ld bc, $0128
    scf
    ld bc, $3701
    ld bc, $1d1c
    ld d, b
    ld d, c
    ld b, h
    ld b, l
    ld d, d
    ld d, e
    ld bc, $3701
    jr z, jr_019_5b8e

    scf

jr_019_5b8e:
    ld bc, $2f01
    add hl, sp
    ld [bc], a
    inc bc
    ld a, [hl-]
    dec sp
    ld [de], a
    inc de
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $2b2a
    inc l
    dec h
    inc c
    dec c
    dec [hl]
    jr c, jr_019_5bb1

jr_019_5bb1:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [$4000], sp
    nop
    jr nz, jr_019_5bc6

jr_019_5bc6:
    nop
    nop
    ld [$0000], sp
    nop
    add d
    nop
    nop
    nop
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
    ld bc, $0000
    ld d, l
    xor d
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    ld h, b
    sbc a
    ld h, b
    sbc a
    nop
    rst $38
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
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld b, b
    ret nz

    ld e, a
    rst $18
    ld b, b
    ret nz

    ld e, a
    rst $18
    ld b, b
    ret nz

    ld a, a
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    inc bc
    inc bc
    ei
    ei
    inc bc
    inc bc
    ei
    ei
    inc bc
    inc bc
    rst $38
    rst $38
    ld bc, $ffff
    rst $38
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
    sbc e
    ld [hl], l
    ld d, l
    xor e
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
    ld [$666e], a
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
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    add b
    add b
    add b
    add b
    add b
    add b
    ld bc, $0103
    inc bc
    ld bc, $0103
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
    nop
    nop
    nop
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
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    xor l
    rst $20
    jp $e742


    and l
    ld a, [hl]
    ld e, d
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
    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    ld e, c
    ld [$08a8], sp
    ld e, a
    ld [$0baf], sp
    ld e, [hl]
    dec bc
    xor a
    dec bc
    ld e, a
    ld a, [bc]
    xor a
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
    nop
    rst $38
    ld b, $f9
    ld b, $f9
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    ld d, l
    xor d
    nop
    nop
    db $fd
    inc bc
    db $fd
    rst $38
    db $fd
    ld a, a
    db $fd
    ccf
    ld e, l
    ccf
    dec e
    ld a, a
    ld d, l
    cp a
    ld d, l
    ccf
    ld e, a
    rst $18
    ld b, b
    ret nz

    ld e, a
    rst $18
    ld b, b
    ret nz

    ld a, a
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld a, [$02fb]
    inc bc
    ld a, [$02fb]
    inc bc
    cp $ff
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    ld l, a
    scf
    and a
    jr c, jr_019_5d86

    inc e
    or a
    rra
    ld d, e
    inc a
    adc c
    inc a
    ld b, a
    rra
    and b
    rrca
    push af
    db $ec
    and $1c
    dec c
    ld hl, sp-$16
    ld hl, sp+$09
    db $fc
    ld [de], a
    db $fc
    push hl
    ld hl, sp+$0a
    ldh a, [$83]
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
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    rst $38
    rst $38
    dec e
    inc bc
    dec c
    inc bc

jr_019_5d86:
    dec b
    inc bc
    rst $38
    rst $38
    dec c
    inc bc
    dec b
    inc bc
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
    rst $38
    rst $38
    inc a
    inc h
    ld a, h
    inc h
    ld a, [hl]
    ld e, d
    rst $20
    and l
    ld c, e
    ld b, d
    and l
    and l
    jp c, $ff5a

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
    ld hl, sp+$0f
    ld [$08ff], sp
    rst $38
    ld hl, sp-$41
    add sp, -$01
    ld l, b
    rst $38
    xor b
    ld a, a
    ld l, b
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
    ld bc, $7fc2
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
    cp a
    ret nz

    cp a
    rst $38
    cp a
    cp $bf
    db $fc
    cp d
    db $fc
    cp b
    cp $aa
    db $fd
    xor d
    db $fc
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
    rra
    ldh a, [rNR10]
    rst $38
    db $10
    rst $38
    rra
    db $fd
    rla
    rst $38
    ld d, $ff
    dec d
    cp $16
    db $fc
    inc d
    cp $14
    cp $16
    rst $38
    dec d
    rst $38
    ld d, $ff
    dec d
    rst $38
    ld d, $ff
    rra
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
    ldh a, [$f0]
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
    add b
    rst $38
    rst $38
    rst $38
    ccf
    jr z, jr_019_5f42

    jr z, jr_019_5f44

    ld l, b
    rst $38
    xor b
    rst $38
    ld l, b
    rst $38
    xor b
    rst $38
    ld l, b
    rst $38
    ld hl, sp-$41
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
    cp $01
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
    and [hl]
    db $fc
    cp a
    rst $20
    cp a
    ldh a, [$bf]
    rst $38
    cp h
    rst $20
    cp a
    rst $20
    cp a
    rst $38
    cp a
    ret nz

    db $fd
    inc bc

jr_019_5f42:
    db $fd
    inc bc

jr_019_5f44:
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
    xor a
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

jr_019_5fed:
    inc bc
    rst $38
    rst $38
    ld [hl], l
    jr nz, jr_019_5fed

    ld e, b
    ld a, a
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
    ld d, l
    inc b
    cp [hl]
    ld a, [de]
    ld a, e
    ld h, a
    pop af
    xor a
    ld b, [hl]
    cp a
    sbc a
    pop af
    rst $30
    adc $9a
    ld hl, sp+$55
    ld bc, $00aa
    ld d, [hl]
    inc bc
    xor a
    ld c, $54
    ld e, $ae
    dec c
    ld a, h
    ld l, $be
    cpl
    ld d, l
    ret nz

    ld [$5540], a
    ret nz

    ld a, [$ad70]
    ld a, b
    ld [hl], d
    or b
    cp l
    ld [hl], h
    ld a, [hl]
    db $f4
    ldh a, [$f0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ldh a, [$f0]
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
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
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rst $38
    rst $38
    rst $38
    rra
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
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
    rrca
    rrca
    rst $38
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
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    ld a, a
    rst $38
    ld a, a
    ret nz

    ld a, a
    rst $18
    ldh a, [$5f]
    ld [hl], b
    rst $18
    ld [hl], b
    rst $18
    ld [hl], b
    rst $18
    rst $38
    nop
    cp $ff
    cp $03
    cp $fb
    rrca
    ld a, [$fb0e]
    ld c, $fb
    ld c, $fb
    rst $38
    ld e, a
    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    ret nz

    rst $38
    ld b, b
    ld a, a
    ret nz

    ld a, a
    ret nz

    ld a, a
    rst $38
    rst $38
    ld a, [$03fe]
    and $03
    and $03
    rst $38
    ld [bc], a
    cp $03
    cp $03
    cp $ff
    jr z, @+$01

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
    ld h, l
    ccf
    db $fd
    rst $20
    db $fd
    rrca
    db $fd
    rst $38
    dec a
    rst $20
    db $fd
    rst $20
    db $fd
    rst $38
    db $fd
    inc bc
    db $10
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [$f0]
    ldh a, [rIF]
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    rst $38
    rra
    rrca
    ld hl, sp+$0f
    ld hl, sp+$0f
    ld hl, sp+$0f
    ld hl, sp+$0f
    ld hl, sp+$0f
    ld hl, sp+$0f
    ld hl, sp-$01
    ld hl, sp-$01
    ld hl, sp+$0f
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$ff01], sp
    ld bc, $01ff
    rst $38
    ld bc, $01ff
    rst $38
    ld bc, $01ff
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    inc c
    dec c
    ld bc, $1c01
    dec e
    ld bc, $5101
    ld d, d
    ld c, d
    ld c, e
    ld d, e
    ld d, h
    ld c, d
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld bc, $0c01
    dec c
    ld bc, $1c01
    dec e
    ld de, $4a11
    ld c, e
    ld de, $4a11
    ld c, e
    ld de, $4a11
    ld c, e
    ld de, $4a11
    ld c, e
    ld c, h
    ld c, h
    ld c, h
    ld c, h
    ld e, $1e
    ld e, $1e
    ld de, $1111
    ld de, $1111
    ld de, $4c11
    ld c, h
    ld c, b
    ld c, c
    ld e, $1e
    ld e, b
    ld e, c
    ld de, $4a11
    ld c, e
    ld de, $4a11
    ld c, e
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $1111
    ld c, d
    ld c, e
    dec b
    dec b
    ld c, d
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $5a01
    ld e, e
    jr nz, @+$22

    jr nz, jr_019_6244

    jr nz, @+$22

    jr nz, @+$22

    jr nz, jr_019_624a

    jr nz, @+$22

    jr nz, @+$22

    jr nz, jr_019_6250

    inc h
    dec h
    inc [hl]
    dec [hl]
    ld b, b
    ld b, c
    ld b, d
    ld b, e
    ld [bc], a
    inc bc
    ld d, l
    ld d, [hl]
    ld [de], a
    inc de
    ld de, $1111
    ld de, $1111

jr_019_6244:
    ld de, $1111
    ld de, $1111

jr_019_624a:
    ld de, $1111
    ld de, $1111

jr_019_6250:
    ld de, $1111
    ld de, $1111
    ld de, $4c11
    ld c, h
    ld c, h
    ld c, h
    ld e, $1e
    ld e, $1e
    ld bc, $0101
    ld bc, $0101
    ld bc, $4c01
    ld c, h
    ld c, h
    ld c, l
    ld d, $17
    ld e, $5d
    ld c, h
    ld c, h
    ld c, h
    ld c, h
    ld e, $1e
    ld e, $1e
    inc h
    dec h
    inc [hl]
    dec [hl]
    ld b, b
    ld b, c
    ld b, d
    ld b, e
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
    add hl, hl
    ld [hl], $37
    scf
    add hl, sp
    ld [hl], $37
    scf
    add hl, sp
    inc a
    ld a, [hl-]
    ld a, [hl-]
    dec sp
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
    ld de, $4411
    ld b, l
    ld de, $0811
    add hl, bc
    ld de, $4611
    ld b, a
    ld de, $1811
    add hl, de
    ld b, h
    ld b, l
    ld c, d
    ld c, e
    ld [$4a09], sp
    ld c, e
    ld b, [hl]
    ld b, a
    ld c, d
    ld c, e
    jr jr_019_62e7

    ld e, d
    ld e, e
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld a, [bc]
    dec bc
    ld bc, $1a01
    dec de
    ld bc, $5001
    ld d, b
    ld c, d
    ld c, e
    ld d, b
    ld d, b
    ld c, d

jr_019_62e7:
    ld c, e
    inc c
    dec c
    ld c, d
    ld c, e
    inc e
    dec e
    ld c, d
    ld c, e
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    inc c
    dec c
    ld bc, $1c01
    dec e
    ld bc, $5001
    ld d, b
    ld c, d
    ld c, e
    ld d, b
    ld d, b
    ld c, d
    ld c, e
    ld a, [bc]
    dec bc
    ld c, d
    ld c, e
    ld a, [de]
    dec de
    ld c, d
    ld c, e
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld a, [bc]
    dec bc
    inc c
    dec c
    ld a, [de]
    dec de
    inc e
    dec e
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    inc c
    dec c
    ld a, [bc]
    dec bc
    inc e
    dec e
    ld a, [de]
    dec de
    ld h, $29
    ld c, b
    ld c, c
    ld [hl+], a
    inc hl
    ld e, b
    ld e, c
    ld [hl+], a
    inc hl
    ld c, d
    ld c, e
    ld [hl-], a
    inc sp
    ld c, d
    ld c, e
    ld c, h
    ld c, h
    inc l
    ld e, h
    ld e, $1e
    ld c, d
    ld c, e
    ld a, [bc]
    dec bc
    ld c, d
    ld c, e
    ld a, [de]
    dec de
    ld c, d
    ld c, e
    ld c, h
    ld c, h
    inc l
    ld c, a
    ld e, $1e
    ld c, d
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    rrca
    ld hl, $4b4a
    rra
    ld sp, $5b5a
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
    ld c, d
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld a, [hl+]
    rrca
    ld e, d
    ld e, e
    dec hl
    rra
    ld c, d
    ld c, e
    ld h, $27
    ld c, d
    ld c, e
    ld [hl], $37
    ld c, d
    ld c, e
    ld [hl], $37
    ld c, d
    ld c, e
    ld [hl], $37
    daa
    daa
    daa
    add hl, hl
    scf
    scf
    scf
    add hl, sp
    scf
    scf
    scf
    add hl, sp
    scf
    scf
    scf
    add hl, sp
    ld [bc], a
    inc bc
    ld d, l
    ld d, [hl]
    ld [de], a
    inc de
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $4c4c
    ld c, h
    ld c, h
    ld e, $1e
    ld h, $29
    ld de, $2211
    inc hl
    ld de, $3211
    inc sp
    ld c, d
    ld c, e
    ld [hl], $37
    ld c, d
    ld c, e
    ld [hl], $37
    ld c, d
    ld c, e
    jr nc, jr_019_640a

    ld c, d
    ld c, e
    jr nc, jr_019_640e

    scf
    scf
    scf
    add hl, sp
    scf
    scf
    scf
    add hl, sp
    ld d, c
    ld d, d
    ld e, $5d
    ld d, e
    ld d, h
    ld b, $07
    ld de, $1111
    ld de, $1111
    ld de, $2411
    dec h

jr_019_640a:
    inc [hl]
    dec [hl]
    ld b, b
    ld b, c

jr_019_640e:
    ld b, d
    ld b, e
    ld c, h
    ld c, h
    ld c, h
    ld c, h
    ld e, $1e
    ld e, $1e
    ld de, $2411
    dec h
    ld de, $4011
    ld b, c
    ld c, h
    ld c, h
    ld c, b
    ld c, c
    ld e, $1e
    ld e, b
    ld e, c
    inc [hl]
    dec [hl]
    ld c, d
    ld c, e
    ld b, d
    ld b, e
    ld c, d
    ld c, e
    ld h, $29
    ld c, h
    ld c, h
    jr z, jr_019_644b

    ld h, $29
    jr c, @+$59

    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld [bc], a
    inc bc
    ld d, l
    ld d, [hl]
    ld [de], a
    inc de
    ld de, $2d11
    ld l, $11

jr_019_644b:
    ld de, $3e3d
    ld de, $1111
    ld de, $0302
    ld de, $1211
    inc de
    ld de, $1111
    ld de, $1111
    ld de, $5511
    ld d, [hl]
    ld c, d
    ld c, e
    ld de, $4a11
    ld c, e
    ld de, $4a11
    ld c, e
    ld de, $4a11
    ld c, e
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld h, $27
    daa
    add hl, hl
    ld [hl], $37
    scf
    add hl, sp
    dec a
    ld a, $11
    ld de, $2f3f
    ld de, $4c11
    ld c, h
    ld c, h
    ld c, h
    ld e, $1e
    ld e, $1e
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    dec b
    dec b
    dec b
    dec b
    ld [hl], $39
    ld bc, $3601
    add hl, sp
    ld bc, $3601
    add hl, sp
    ld bc, $3601
    add hl, sp
    ld bc, $5001
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld bc, $0101
    ld bc, $0101
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld a, [hl+]
    rrca
    ld c, d
    ld c, e
    dec hl
    rra
    dec b
    dec b
    dec b
    dec b
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    dec b
    dec b
    ld b, h
    ld b, l
    ld bc, $0801
    add hl, bc
    ld bc, $4601
    ld b, a
    ld bc, $1801
    add hl, de
    ld b, h
    ld b, l
    ld b, h
    ld b, l
    ld [$0809], sp
    add hl, bc
    ld b, [hl]
    ld b, a
    ld b, [hl]
    ld b, a
    jr @+$1b

    jr jr_019_6519

    ld de, $1111
    ld de, $1111
    ld de, $2611
    add hl, hl
    ld h, $29
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld [hl], $39
    ld bc, $3601
    add hl, sp
    ld bc, $3601

jr_019_6519:
    add hl, sp
    ld bc, $3601
    add hl, sp
    ld bc, $3601
    add hl, sp
    ld bc, $3601
    add hl, sp
    ld bc, $2601
    add hl, hl
    ld bc, $3201
    inc sp
    ld bc, $5001
    ld d, b
    ld b, h
    ld b, l
    ld h, $29
    ld [$3609], sp
    add hl, sp
    ld b, [hl]
    ld b, a
    ld [hl], $39
    jr jr_019_6559

    ld c, h
    ld c, h
    ld c, h
    ld c, h
    ld e, $1e
    ld e, $1e
    ld a, [bc]
    dec bc
    ld bc, $1a01
    dec de
    ld bc, $4a01
    ld c, e
    daa
    daa
    ld c, d
    ld c, e
    scf
    scf
    ld c, d

jr_019_6559:
    ld c, e
    scf
    scf
    ld c, d
    ld c, e
    scf
    scf
    ld c, d
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0404
    inc b
    inc b
    inc d
    inc d
    inc d
    inc d
    ld h, $29
    ld d, b
    ld d, b
    jr z, @+$17

    ld h, $29
    jr c, jr_019_65e1

    ld [hl+], a
    inc hl
    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld d, b
    ld d, b
    ld h, $29
    ld h, $29
    jr z, jr_019_65ad

    ld [hl+], a
    inc hl
    jr c, jr_019_65f3

    ld [hl-], a
    inc sp
    ld [hl-], a
    inc sp
    ld de, $1111
    ld de, $1111
    ld de, $0411
    inc b
    inc b
    inc b
    inc d

jr_019_65ad:
    inc d
    inc d
    inc d
    ld de, $1111
    ld de, $1111
    ld de, $2611
    daa
    daa
    daa
    ld [hl], $37
    scf
    scf
    ld de, $1111
    ld de, $1111
    ld de, $2711
    daa
    daa
    add hl, hl
    scf
    scf
    scf
    add hl, sp
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld de, $1111
    ld de, $1111
    ld de, $4e11

jr_019_65e1:
    ld c, a
    ld c, h
    ld c, h
    ld c, d
    ld c, e
    ld e, $1e
    ld c, d
    ld c, e
    ld bc, $4a01
    ld c, e
    ld bc, $3601
    scf
    scf

jr_019_65f3:
    scf
    inc a
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld de, $1111
    ld de, $1111
    ld de, $3711
    scf
    scf
    add hl, sp
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    dec sp
    ld de, $1111
    ld de, $1111
    ld de, $c811
    ret z

    ret nz

    ret nz

    adc b
    adc b
    jr jr_019_6630

    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    rst $18
    and b
    ret nz

    cp a
    rst $38
    add b
    rst $38
    rst $38
    and b
    rst $38
    cp a
    rst $38
    and b
    rst $38
    rst $38
    ld a, a

jr_019_6630:
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
    rlca
    rst $18
    nop
    inc a

Jump_019_6642:
    nop
    adc c
    nop
    ld h, b
    nop
    rst $30
    nop
    rst $20
    rrca
    rst $28
    ld sp, hl
    rst $30
    ld a, [c]
    ld e, [hl]
    nop
    inc a
    nop
    adc c
    inc bc
    ld h, e
    inc e
    db $fc
    ld a, e
    ei
    or [hl]
    or [hl]
    ld h, [hl]
    ld h, [hl]
    ld l, h
    ld l, h
    ld bc, $7e3d
    cp $89
    adc c
    ld [de], a
    inc de
    ld [hl+], a
    inc hl
    ld [hl+], a
    inc hl
    ld b, d
    ld b, e
    ld b, d
    ld b, e
    rst $38
    rst $38
    ret nz

    rst $38
    ccf
    rst $38
    ret nz

    ret nz

    add c
    add c
    add d
    add d
    add e
    add e

Jump_019_667e:
    add a
    add h
    sbc h
    cp h
    db $e4
    push hl
    ld b, a
    ld b, a
    adc b
    adc b
    ld [$0808], sp
    ld [$0888], sp
    call nz, $8084
    sbc d
    add b
    sbc d
    add b
    add b
    ld a, a
    ld a, a
    inc a
    inc h
    inc h
    rst $20
    jr @+$01

    nop
    nop
    nop
    rst $38
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
    nop
    nop
    xor a
    nop
    rst $18
    nop
    rst $38
    nop
    rst $38
    nop
    cp a
    nop
    ld [hl], l
    nop
    cp e
    nop
    rst $38
    nop
    nop
    inc a
    nop
    adc c
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
    inc a
    nop
    adc c
    db $fc
    db $fc
    inc bc
    inc bc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc a
    nop
    adc c
    nop
    ld h, b
    nop
    rst $30
    ret nz

    rst $20
    ccf
    ccf
    inc sp
    ld a, $0e
    rrca
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
    rst $38
    rst $38
    add e
    cp $fe
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
    ldh [$fb], a
    sub b
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
    ld bc, $03e7
    sbc d
    ld b, $df
    nop
    inc a
    ld bc, $0789
    ld h, a
    add hl, de
    rst $38
    ld [hl], e
    rst $28
    call z, $b0bc
    ld hl, sp-$24
    call c, Call_000_3b3c
    pop hl
    rst $18
    rst $08
    ld a, [hl]
    ld a, h
    rst $38
    ld [hl], e
    jp nc, $f392

    rst $38
    adc h
    add b
    rst $38
    ld a, [hl]
    sbc $d0
    db $fc
    call c, Call_000_2474
    db $fc
    db $fc
    inc b
    ld bc, $f9f9
    add hl, bc
    add hl, bc
    ld sp, hl
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
    call c, Call_019_4342
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    adc e
    adc b
    sub c
    sub b
    and c
    cp a
    sbc $c0
    add b
    cp a
    cp a
    add b
    sbc a
    add b
    adc a
    add b
    db $e4
    ld b, a
    db $f4
    and h
    db $fc
    or h
    db $fc
    xor h
    ldh a, [rNR41]
    ld hl, sp+$20
    ld hl, sp+$20
    db $fc
    jr nz, jr_019_6798

    rst $38
    rst $28
    jr nc, @-$03

    ld b, a
    or a
    ld c, a

jr_019_6798:
    rst $30
    adc a
    rst $30
    adc a
    di
    adc a
    ldh a, [$9f]
    ld hl, sp-$01
    ei
    ld b, $f9
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    db $fd
    rst $38
    ld sp, hl
    rst $38
    ld bc, $ffff
    inc a
    jp $8142


    add c
    jp $ff81


    ld b, d
    inc a
    rst $38
    inc a
    rst $20
    sbc c
    ld a, [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_019_67c8:
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
    ld bc, $0201
    ld [bc], a
    dec c
    inc c
    db $10
    rra
    rrca
    jr nz, jr_019_67df

jr_019_67df:
    rra
    ld a, $fb
    ld c, c
    ld c, a
    cp a
    sbc a
    rst $38
    jr z, jr_019_67c8

    ld c, b
    sbc a
    adc b
    sbc a
    adc b
    sbc a
    ld [$83fe], sp
    ld bc, $ffff
    cp $01
    ld bc, $0001
    ld bc, $0100
    nop
    ld bc, $f800
    db $ec
    inc d
    db $fd
    cp $0a
    add [hl]
    rst $38
    rst $38
    rst $00
    db $e3
    rst $38
    rst $38
    db $d3
    pop af
    rst $18
    ld c, $3b
    dec de
    sub a
    inc [hl]
    ld l, h
    ld l, b
    ret c

    ld d, b
    ldh a, [$d0]
    or b
    and b
    rst $20
    and e
    db $e4
    nop
    adc b
    nop
    adc b
    nop
    adc b
    nop
    adc b
    nop
    adc b
    nop
    adc b
    nop
    adc b
    nop
    adc b
    rst $38
    add b
    add b
    rst $38
    rst $38
    add b
    add b
    rst $38
    rst $38
    add b
    add b
    rst $38
    rst $38
    add b
    add b
    rst $38
    ld sp, hl
    add hl, bc
    add hl, bc
    ld sp, hl
    ld sp, hl
    add hl, bc
    add hl, bc
    ld sp, hl
    ld sp, hl
    add hl, bc
    add hl, bc
    ld sp, hl
    ld sp, hl
    add hl, bc
    add hl, bc
    ld sp, hl
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    sbc b
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    ld [c], a
    db $e3
    jp nz, $c1c3

    pop bc
    pop bc
    pop bc
    ret nz

    ret nz

    ldh [$a0], a
    add a
    add b
    add e
    add b
    add c
    add b
    add b
    add b
    ld b, b
    ret nz

    ld a, a
    rst $38
    add b
    rst $38
    rst $38
    ld a, a
    db $fc

jr_019_6881:
    jr nz, jr_019_6881

jr_019_6883:
    jr nz, jr_019_6883

    jr nz, @+$01

    jr nz, jr_019_6908

    jr nz, @+$01

    and b
    rst $38
    and b
    ldh [$bf], a
    or b
    ld e, a
    db $ec
    ld e, a
    db $e3
    ld e, a
    ldh a, [$3f]
    rst $38
    rlca
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    inc bc
    rst $38
    rlca
    rst $38
    ei
    cp $07
    db $fc
    rst $38
    ldh a, [rIE]
    nop
    rst $38
    nop
    nop
    rst $38
    nop
    inc a
    nop
    adc c
    nop
    ld h, b
    ld bc, $01f7
    rst $20
    ld bc, $01e7
    sbc e
    ld bc, $00dd
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    rlca
    nop
    inc bc
    nop
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    sbc a
    ld [$08df], sp
    rst $18
    ld [$08ff], sp
    rst $38
    ld [$087f], sp
    ccf
    ld [$f80f], sp
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    rst $38
    pop de
    pop af
    rst $18
    rst $38
    pop de
    pop af
    rst $18

jr_019_6908:
    rst $38
    pop de
    pop af
    rst $18
    rst $38
    pop de
    pop af
    rst $18
    jp $c3c4


    call nz, $e4e3
    and b
    and a
    ld d, b
    ret nc

    ld c, b
    ret z

    daa
    and a
    inc de
    jp nc, $3c3c

    ld h, [hl]
    jp Jump_019_6642


    ld b, d
    rst $38
    ld h, [hl]
    jp $c366


    nop
    cp a
    nop
    call c, $ff80
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    add b
    rst $38
    rst $38
    rst $38
    ld sp, hl
    add hl, bc
    add hl, bc
    ld sp, hl
    ld sp, hl
    add hl, bc
    add hl, bc
    ld sp, hl
    ldh a, [$08]
    inc b
    db $fc
    db $fc
    inc b
    inc b
    db $fc
    sbc b
    sbc b
    sub b
    sub b
    add h
    add h
    inc c
    inc c
    ld c, h
    ld c, h
    add $c6
    add $c6
    add $c6
    pop hl
    and b
    ld [hl], c
    ld d, b
    ld a, e
    ld c, b
    ccf
    inc h
    ccf
    inc hl
    rra
    db $10
    rra
    inc c
    rra
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
    rst $38
    rst $38
    ld bc, $01ff
    rst $38
    rst $38
    rst $38
    jr nz, @+$01

    jr nz, @+$01

    ld b, b
    rst $38
    ld b, b
    rst $38
    ld b, b
    rst $38
    ld b, b
    rst $38
    ld b, b
    rst $38
    ld a, a
    rst $38
    nop
    rst $38
    rra
    ldh [$7f], a
    sbc a
    rst $38
    ldh [rIE], a
    ldh [rIE], a
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    ldh a, [rIF]
    db $fc
    di
    cp $0f
    cp $0f
    cp $ff
    db $fc
    rst $38
    rst $38
    rst $38
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
    ld bc, $ffff
    rst $38
    ld bc, $ffff
    rst $38
    ld bc, $ffff
    rst $38
    ld bc, $ffff
    rst $38
    add b
    nop
    nop
    rst $38
    add b
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rlca
    rst $38
    rra
    ld [$081f], sp
    rra
    ld [$181f], sp
    ld a, a
    jr @+$01

    ld l, b
    rst $38
    adc b
    rst $38
    rrca
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $ff00
    ld bc, $feff
    nop
    nop
    inc a
    inc a
    cp $fe
    ld bc, $01ff
    ld bc, $d901
    ld bc, $01d1
    ld bc, $3909
    dec b
    adc h
    inc bc
    ld h, d
    ld bc, $00f7
    rst $20
    nop
    rst $20
    nop
    sbc e
    nop
    call c, $9c94
    db $f4
    ld a, h
    db $fc
    inc e
    rst $38
    rlca
    rst $38
    add c
    ld a, a
    ret nz

    ccf
    and b
    rra
    ret c

    rst $38
    adc h
    sub d
    di
    di
    sub d
    call z, $f37f
    call z, Call_000_3ff8
    rst $38
    rlca
    rst $38
    nop
    ld hl, sp+$04
    ld [bc], a
    cp $fe
    ld [bc], a
    nop
    cp $ff
    ld hl, $df70
    rst $38
    ld d, b
    ldh a, [rIE]
    ld h, e
    ld h, e
    ld h, e
    ld h, e
    ld [hl], c
    ld [hl], c
    jr nc, @+$32

    jr c, jr_019_6a92

    dec e
    inc e
    adc a
    adc a
    ld b, a
    rst $00
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
    rst $38
    nop
    rst $38
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0129
    xor c
    ld bc, $fe01
    cp $3c
    inc h
    inc h
    rst $20
    jr @+$01

    nop
    nop
    nop
    rst $38

jr_019_6a92:
    ld bc, $0eff
    cp $1e
    ld a, [c]
    inc [hl]
    db $ec
    inc [hl]
    db $ec
    ld h, h
    call c, $dc64
    cp $ff
    ccf
    ld hl, $5f61
    ld h, c
    ld e, a
    ld h, c
    ld e, a
    ld h, c
    ld e, a
    ld h, c
    ld e, a
    daa
    add hl, sp
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    add b
    nop
    add b
    nop
    nop
    rst $38
    nop
    rst $38
    db $fc
    rst $38
    ld a, [$faff]
    rrca
    ld a, [bc]
    rst $38
    ld a, [bc]
    rrca
    ld a, [bc]
    rrca
    ld a, [bc]
    rrca
    ld a, [bc]
    rst $38
    ld a, [bc]
    rrca
    ld a, [$02ff]
    rst $38
    ld [bc], a
    rst $38
    db $fc
    rst $38
    ldh [rIE], a
    rst $38
    rra
    rst $38
    jr c, @+$01

    ld a, a
    ld hl, sp+$6f
    ld hl, sp+$1f
    ld hl, sp+$3f
    ld sp, hl
    ld a, a
    ld a, [$ff6f]
    rst $38
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
    ld bc, $82ff
    rst $38
    rst $38
    ld hl, $7fc1
    cp a
    jp $ff03


    ld a, $c7
    ld c, $fb
    inc a
    rst $10
    db $fc
    db $e4
    ei
    dec b
    inc bc
    db $fd
    rst $38
    ld bc, $ffff
    dec b
    rst $38
    db $fd
    rst $38
    dec b
    rst $38
    rst $38
    cp $07
    ld a, $01
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
    call c, Call_000_00ff
    rst $38
    ret nz

    ld a, a
    ld a, b
    rra
    rst $38
    rlca
    rst $20
    ld bc, $00e7
    sbc e
    nop
    call c, $0fff
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld hl, sp-$01
    rst $38
    ccf
    cp a
    inc bc
    rst $18
    nop
    nop
    inc a
    inc a
    ld a, a
    ld a, a
    add b
    rst $38
    add b
    add b
    add b
    sub d
    add b
    sbc d
    add b
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
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld a, a
    ld a, a
    xor d
    add b
    ret nz

    cp a
    adc d
    and b
    rst $18
    and b
    rst $18
    and b
    rst $18
    and b
    rst $18
    and b
    cp $fe
    xor e
    ld bc, $fd01
    xor e
    dec b
    ei
    dec b
    ei
    dec b
    ei
    dec b
    ei
    dec b
    ld h, h
    call c, $de62
    ld h, d
    sbc $6d
    rst $18
    jr nc, @+$01

    jr nz, @+$01

    rra
    rst $38
    rlca
    rst $38
    ld hl, $7f3f
    ld a, a
    pop de
    pop de
    sub c
    sub c
    rst $38
    rst $38
    add c
    rst $38
    rst $38
    rst $38
    ldh [rIE], a
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
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld hl, sp-$74
    ld hl, sp+$09
    ldh a, [rNR10]
    ldh a, [$37]
    ldh [$e7], a
    ldh [$e7], a
    ret nz

    db $db
    add b
    call c, $ffff
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
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
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
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [de]
    ld a, [de]
    ld a, [bc]
    ld c, b
    ld c, c
    ld c, d
    ld c, e
    ld e, b
    ld e, c
    inc a
    ld c, h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld [bc], a
    inc bc
    db $10
    ld de, $1312
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc b
    dec b
    ld b, $07
    nop
    dec d
    ld d, $17
    ld [hl-], a
    dec sp
    inc d
    inc d
    ld [hl-], a
    dec sp
    inc d
    inc d
    add hl, bc
    add hl, bc
    dec bc
    dec bc
    jr jr_019_6c77

    jr jr_019_6c79

    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    inc d
    inc d
    inc d
    inc d
    inc c
    dec c
    ld c, $0f
    inc e
    dec e
    ld e, $1f
    jr nz, @+$23

    ld [hl+], a
    inc hl
    jr nc, @+$23

    ld [hl+], a

jr_019_6c77:
    inc sp
    ld b, b

jr_019_6c79:
    ld b, c
    ld b, d
    ld b, e
    inc d
    ld d, c
    ld d, d
    ld d, e
    inc h
    dec h
    ld h, $27
    inc [hl]
    dec [hl]
    ld [hl], $37
    ld b, h
    ld b, l
    ld b, l
    ld b, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    jr z, jr_019_6cbb

    jr z, jr_019_6cbd

    jr c, jr_019_6ccf

    jr c, jr_019_6cd1

    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    inc l
    dec l
    ld l, $2f
    ld a, $3d
    ld a, $2f
    ld b, l
    ld c, l
    ld c, [hl]
    ld c, a
    ld d, l
    ld e, l
    ld e, d
    ld e, e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]

jr_019_6cbb:
    ld a, [bc]
    ld a, [bc]

jr_019_6cbd:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
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

jr_019_6ccf:
    inc d
    ld d, [hl]

jr_019_6cd1:
    ld d, a
    ld d, [hl]
    ld d, a
    ld bc, $0150
    ld d, b
    ld d, [hl]
    ld d, a
    ld d, [hl]
    ld d, a
    ld bc, $0150
    ld d, b
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld e, h
    ld sp, $1431
    inc d
    ld sp, $1431
    inc d
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $1414
    ld sp, $1431
    inc d
    ld sp, $1431
    inc d
    ld sp, $1431
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    ld sp, $3131
    ld sp, $3131
    ld sp, $3a31
    ld a, [hl-]
    ld a, [hl-]
    ld a, [hl-]
    ld sp, $1431
    inc d
    ld sp, $1431
    inc d
    ld sp, $1431
    inc d
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld d, h
    ccf
    ld a, [bc]
    ld a, [bc]
    ld [$3247], sp
    dec sp
    ld sp, $3231
    dec sp
    ld sp, $3231
    dec sp
    inc d
    inc d
    ld [hl-], a
    dec sp
    inc d
    inc d
    ld sp, $3131
    ld sp, $3131
    ld sp, $1431
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor $c7
    cp $bb
    rst $38
    cp e
    cp $c7
    cp h
    rst $38
    add b
    rst $38
    ld h, b
    ld a, a
    rrca
    rrca
    rlca
    rst $38
    ld bc, $ffff
    cp $07
    db $fc
    rlca
    rst $38
    ld bc, $06ff
    cp $f0
    ldh a, [rIE]
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
    nop
    nop
    rst $38
    inc bc
    rst $38
    rrca
    db $fc
    rst $38
    db $10
    ld a, $e1
    ld a, h
    jp nz, $dc60

    rst $30
    rrca
    ld a, l
    ld a, [c]
    ld hl, sp+$07
    ret nz

    jr c, jr_019_6de9

jr_019_6de9:
    ret nz

    nop
    rlca
    nop
    ld [$1700], sp
    rst $28
    ldh a, [$be]
    ld c, a
    rra
    ldh [$03], a
    inc e
    nop
    inc bc
    nop
    ldh [rP1], a
    stop
    add sp, -$01
    nop
    nop
    rst $38
    ret nz

    rst $38
    ldh a, [$3f]
    rst $38
    ld [$877c], sp
    ld a, $43
    ld b, $3b
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
    ld [$d81e], a
    xor [hl]
    db $ec
    sbc h
    ret c

    xor b
    ldh [$30], a
    add b
    ret nz

    nop
    nop
    nop
    nop
    rst $38
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
    nop
    rst $38
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
    nop
    nop
    rst $38
    rst $38
    add b
    add b
    add b
    cp a
    add h
    cp b
    adc b
    or b
    add b
    cp [hl]
    add b
    cp [hl]
    nop
    nop
    rst $38
    rst $38
    ld bc, $0101
    db $fd
    ld bc, $017d
    cp l
    ld bc, $413d
    dec e
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
    sbc b
    push hl
    ld hl, sp-$7c
    ldh [$9e], a
    sbc [hl]
    pop hl
    rst $38
    add b
    rst $38
    ret nz

    cp a
    ret nz

    cp a
    ldh [rP1], a
    rst $10
    nop
    ld [$0700], sp
    nop
    nop
    nop
    pop bc
    ret nz

    jr c, @-$06

    rlca
    db $fd
    ld [bc], a
    nop
    db $eb
    nop
    stop
    ldh [rP1], a
    nop
    nop
    add e
    inc bc
    inc e
    rra
    ldh [$bf], a
    ld b, b
    add hl, de
    and a
    rra
    ld hl, $7907
    ld a, c
    add a
    rst $38
    ld bc, $03ff
    db $fd
    inc bc
    db $fd
    rlca
    xor a
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
    add b
    nop
    ld b, b
    nop
    jr nz, jr_019_6f56

jr_019_6f56:
    stop
    jr z, jr_019_6f5a

jr_019_6f5a:
    ld b, h
    nop
    add d
    nop
    ld bc, $8000
    nop
    ld b, b
    nop
    ld a, [hl]
    ld a, [hl]
    rst $38
    and c
    rst $38
    and c
    and c
    and c
    and c
    and c
    and c
    and c
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
    add a
    cp b
    add c
    cp [hl]
    add c
    cp [hl]
    add b
    add b
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    pop hl
    dec e
    pop hl
    dec c
    pop af
    dec c
    ld bc, $ff01
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    add b
    nop
    ld b, b
    nop
    ld a, [hl]
    ld a, [hl]
    rst $38
    add l
    rst $38
    add l
    add l
    add l
    add l
    add l
    add l
    add l
    add b
    nop
    ld b, b
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    sbc a
    ldh a, [$87]
    db $fc
    add a
    ld sp, hl
    adc e
    db $f4
    add a
    ld hl, sp-$35
    db $f4
    rst $00
    ld hl, sp-$15
    db $f4
    db $fd
    ld [bc], a
    db $fd
    ld [bc], a
    db $fd
    ld [bc], a
    db $fd
    ld h, d
    rst $38
    rrca
    cp $04
    cp $c8
    rst $38
    db $d3
    cp a
    ld b, b
    cp a
    ld b, b
    cp a
    ld b, b
    cp a
    ld b, [hl]
    rst $38
    ldh a, [$7f]
    jr nz, @+$81

    inc de
    rst $38
    set 7, c
    rrca
    pop hl
    ccf
    pop hl
    sbc a
    pop de
    cpl
    pop hl
    rra
    db $d3
    cpl
    db $e3
    rra
    rst $10
    cpl
    add b
    rst $38
    rst $38
    rst $38
    and b
    rst $38
    and l
    ld a, [$ffbf]
    and b
    ldh [$ef], a
    ldh [$af], a
    ld h, b
    nop
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    nop
    db $fd
    ld a, [$0506]
    push af
    ld b, $f6
    dec b
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
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    and e
    cp $a3
    and d
    rst $38
    and c
    rst $38
    ld a, [hl]
    ld a, [hl]
    nop
    nop
    add d
    nop
    ld bc, $5700
    inc bc
    xor h
    inc c
    ld d, b
    db $10
    or e
    jr nz, @+$01

jr_019_7079:
    jr nz, @+$01

    jr nz, jr_019_7079

    inc hl
    ei
    db $f4
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
    nop
    rst $38
    rst $38
    nop
    push de
    ret nz

    ld a, [hl-]
    jr nc, jr_019_70a2

    ld [$04ce], sp
    rst $38
    inc b
    rst $38
    inc b
    ccf
    call nz, Call_000_2fdf
    nop
    nop

jr_019_70a2:
    nop
    nop
    nop
    nop
    nop
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
    push bc
    ld a, a
    push bc
    ld b, l
    rst $38
    add l
    rst $38
    ld a, [hl]
    ld a, [hl]
    nop
    nop
    add d
    nop
    ld bc, $ff00
    nop
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    jr z, jr_019_70ca

jr_019_70ca:
    ld b, h
    nop
    add d
    nop
    ld bc, $b700
    ld hl, sp-$61
    db $fc
    sbc a
    rst $38
    sbc e
    rst $30
    sub a
    ld hl, sp-$65
    db $f4
    sub a
    ld hl, sp+$1b
    db $f4
    db $fc
    rst $10
    rst $38
    rla
    db $fc
    rla
    rst $38
    db $eb
    sbc a
    db $fc
    add e
    rst $38
    add b
    rst $38
    cp h
    rst $38
    ccf
    db $eb
    rst $38
    add sp, $3f
    add sp, -$01
    rst $10
    ld sp, hl
    ccf
    pop bc
    rst $38
    rlca
    cp $07
    db $fc
    db $ed
    rra
    ld sp, hl
    ccf
    ld sp, hl
    rst $38
    reti


    rst $28
    jp hl


    rra
    reti


    xor a
    jp hl


    sbc a
    ret c

    xor a
    cpl
    jr nz, jr_019_7142

    jr nz, jr_019_7135

jr_019_7115:
    jr nz, jr_019_7156

    jr nz, jr_019_7158

    cpl
    jr c, @+$31

    ccf
    jr z, jr_019_715e

    jr c, jr_019_7115

    inc b
    db $f4
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
    nop
    nop
    nop
    nop

jr_019_7135:
    nop
    nop
    nop
    nop
    nop
    rra
    rra
    jr nz, jr_019_715e

    cpl
    jr nz, jr_019_7141

jr_019_7141:
    nop

jr_019_7142:
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
    db $f4
    inc b
    rst $18
    and b
    rst $08
    ldh a, [$e7]
    cp b

jr_019_7156:
    di
    sbc h

jr_019_7158:
    ld sp, hl
    sbc [hl]
    db $f4
    sbc a
    ld a, [c]
    sbc a

jr_019_715e:
    ld sp, hl
    sbc a
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
    ld e, a
    ld c, b
    ld e, a
    ld c, b
    ld e, a
    ld c, b

jr_019_7176:
    ld a, a
    ld c, b
    ld a, l
    ld c, b
    ld [hl-], a
    inc a
    inc c
    rrca
    inc bc
    inc bc
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    ld d, l
    nop
    xor d
    nop
    nop
    rst $38

jr_019_718e:
    rst $38
    rst $38
    ld a, [$fa12]
    ld [de], a
    ld a, [$fe12]
    ld [de], a
    ld a, [hl]
    ld [de], a
    adc h
    inc a
    jr nc, jr_019_718e

    ret nz

    ret nz

    ld d, l
    nop
    xor d
    nop
    ld d, l
    nop

jr_019_71a6:
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
    ld a, a
    add b
    cp a
    ld b, b
    rst $18
    jr nz, jr_019_71a6

    db $10
    rst $10
    jr z, jr_019_7176

    ld b, h
    ld a, l
    add d
    cp $01
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop

jr_019_71c7:
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
    nop
    rst $38
    nop
    nop
    rst $38
    nop
    nop
    ld bc, $0201
    ld [bc], a
    dec b
    inc b
    dec bc
    ld [$1017], sp
    cpl
    jr nz, jr_019_724c

    ld b, b
    cp a
    add b
    add b
    add b
    ld b, b
    ld b, b
    and b
    jr nz, jr_019_71c7

    db $10
    add sp, $08
    db $f4
    inc b
    ld a, [$fd02]
    ld bc, $ffff
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
    rst $38
    rst $38
    rst $38
    add c
    rst $38
    jp $c3bd


    cp l
    jp $c3bd


    cp l
    rst $38
    ld a, [hl]
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
    rst $38
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
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd
    db $fd
    ld bc, $01fd

jr_019_724c:
    db $fd
    ld bc, $01fd
    db $fc
    sub a
    ld l, [hl]
    ld e, e
    ccf
    dec a
    inc bc
    ld c, $01
    rlca
    nop
    inc bc
    nop
    ld bc, $0000
    ld d, a
    ld a, b
    dec de
    ld [hl], h
    scf
    jr c, jr_019_7282

    inc d
    rlca
    inc c
    ld bc, $0003
    nop
    nop
    nop
    ei
    dec b
    di
    rrca
    rst $20
    dec e
    rst $08
    add hl, sp
    sbc a
    ld a, c
    cpl
    ld sp, hl
    ld c, a
    ld sp, hl
    sbc a
    ld sp, hl
    ccf
    jp hl


jr_019_7282:
    db $76
    jp c, $bcfc

    ret nz

    ld [hl], b
    add b
    ldh [rP1], a
    ret nz

    nop
    add b
    nop
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
    ld bc, $8038
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rra
    rra
    dec bc
    inc c
    rra
    rra
    dec de
    inc e
    rra
    rra
    dec hl
    inc l
    rra
    rra
    dec sp
    inc a
    dec c
    ld c, $1f
    rra
    dec e
    ld e, $1f
    rra
    ld e, e
    ld e, h
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
    db $10
    db $10
    db $10
    db $10
    db $10
    rlca
    ld [$2009], sp
    rla
    jr jr_019_73b5

    jr nc, @+$29

    jr z, @+$2b

    db $10
    db $10
    db $10
    db $10
    ld a, [bc]
    db $10
    db $10
    db $10
    ld a, [de]
    dec h
    ld h, $26
    ld a, [hl+]
    dec [hl]
    ld [hl], $36
    db $10
    db $10
    db $10
    db $10
    db $10

jr_019_73b5:
    db $10
    db $10
    rlca
    ld h, $26
    jr nz, @+$19

    ld [hl], $36
    jr nc, jr_019_73e7

    db $10
    db $10
    db $10
    db $10
    ld [$0a09], sp
    db $10
    jr jr_019_73e3

    ld a, [de]
    dec h
    jr z, jr_019_73f7

    ld a, [hl+]
    dec [hl]
    ld b, l
    scf
    jr c, jr_019_740d

    rra
    ld d, b
    ld bc, $1f02
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld a, [hl-]
    ld b, l
    ld b, l

jr_019_73e3:
    ld b, l
    rrca
    rra
    rra

jr_019_73e7:
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld b, l
    ld b, l
    ld b, l
    scf
    rra
    rra
    rra

jr_019_73f7:
    ld d, b
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    jr c, jr_019_743b

    ld a, [hl-]
    ld b, l
    ld bc, $0f02
    rra
    rra
    rra
    rra
    rra
    rra

jr_019_740d:
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
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld b, a
    ld b, a
    ld b, a
    ld b, a
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
    cpl
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

jr_019_743b:
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
    dec a
    ld a, $1f
    rra
    dec sp
    inc a
    rra
    rra
    rra
    ld c, b
    ld c, d
    ld c, d
    ld c, b
    ld b, b
    ld b, b
    ld de, $404d
    ld b, b
    ld hl, $404d
    ld b, b
    ld e, e
    ld c, d
    ld c, d
    ld c, c
    rra
    ld [de], a
    ld b, b
    ld b, b
    ld c, c
    ld [hl+], a
    ld b, b
    ld b, b
    ld c, [hl]
    ld e, h
    ld b, b
    ld b, b
    ld c, [hl]
    inc [hl]
    inc [hl]
    inc [hl]
    inc [hl]
    ld b, h
    ld sp, $3232
    rra
    ld b, c
    ld b, d
    ld b, d
    rra
    rra
    rra
    rra
    inc [hl]
    inc [hl]
    inc [hl]
    inc [hl]
    inc sp
    ld b, h
    ld b, h
    ld b, h
    ld b, e
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ccf
    ld b, b
    ld b, b
    ld b, b
    ld c, a
    ccf
    ld b, b
    ld b, b
    rra
    ld c, a
    ld c, e
    ld c, h
    rra
    rra
    rra
    rra
    ld b, b
    ld b, b
    ld b, b
    ld d, c
    ld b, b
    ld b, b
    ld d, c
    ld d, d
    ld c, h
    ld c, e
    ld d, d
    rra
    rra
    rra
    rra
    rra
    inc de
    inc d
    inc [hl]
    inc [hl]
    inc hl
    inc h
    ld b, h
    ld b, h
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    inc [hl]
    inc [hl]
    inc de
    inc d
    ld b, h
    ld b, h
    inc hl
    inc h
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
    dec a
    ld a, $1f
    rra
    dec sp
    inc a
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
    dec a
    ld a, $1f
    rra
    dec sp
    inc a
    dec a
    ld a, $1f
    rra
    dec sp
    inc a
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
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld e, b
    ld e, b
    ld e, b
    ld e, b
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, e
    ld e, h
    db $10
    db $10
    inc bc
    inc bc
    db $10
    db $10
    inc b
    inc b
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    db $10
    db $10
    dec b
    ld b, $10
    db $10
    dec d
    ld d, $1f
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    dec l
    ld d, a
    ld e, e
    ld e, h
    ld e, e
    ld e, b
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld e, l
    ld e, l
    ld e, l
    ld e, l
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    dec l
    ld l, $10
    db $10
    ld e, c
    ld e, d
    db $10
    db $10
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    db $10
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    dec l
    ld l, $2f
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    dec l
    ld d, a
    ld d, a
    ld d, a
    ld e, e
    ld e, b
    ld e, b
    ld e, b
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld e, b
    ld e, b
    ld e, b
    ld e, b
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld d, a
    ld l, $2f
    cpl
    ld e, b
    ld e, h
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    ld e, c
    ld e, d
    cpl
    cpl
    db $10
    db $10
    dec l
    ld l, $10
    db $10
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld d, a
    ld d, a
    ld d, a
    ld l, $58
    ld e, b
    ld e, b
    ld e, h
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    dec l
    ld d, a
    ld d, a
    ld d, a
    ld e, e
    ld e, b
    ld e, b
    ld e, b
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    dec l
    ld d, a
    ld e, c
    ld e, d
    ld e, e
    ld e, b
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    ld d, a
    ld l, $59
    ld e, d
    ld e, b
    ld e, h
    ld e, e
    ld e, h
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld d, a
    ld l, $2d
    ld l, $58
    ld e, h
    ld e, c
    ld e, d
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    dec l
    ld d, a
    ld d, a
    ld l, $5b
    ld e, b
    ld e, b
    ld e, h
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    dec l
    ld d, a
    ld e, c
    ld e, d
    dec l
    ld d, a
    ld e, c
    ld e, d
    inc [hl]
    inc [hl]
    ld e, c
    ld e, d
    ld b, h
    ld b, h
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
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
    ld d, a
    ld l, $2d
    ld l, $57
    ld l, $59
    ld e, d
    inc [hl]
    inc [hl]
    ld e, c
    ld e, d
    ld b, h
    ld b, h
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    dec l
    ld l, $1f
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    ld e, c
    ld e, d
    rra
    rra
    dec l
    ld d, a
    ld d, a
    ld l, $5b
    ld e, b
    ld e, b
    ld e, h
    dec bc
    inc c
    dec c
    ld c, $1b
    inc e
    dec e
    ld e, $2b
    inc l
    ld e, e
    ld e, h
    dec sp
    inc a
    rra
    rra
    rra
    rra
    ld d, e
    ld d, h
    rra
    rra
    ld d, l
    ld d, [hl]
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    db $d3
    rst $38
    inc d
    ld b, c
    xor d
    nop
    rst $18
    nop
    ld a, d
    add l
    push af
    ld a, [bc]
    ld a, [$bf05]
    ld b, b
    nop
    add b
    ld b, b
    ret nz

    ld [hl], b
    ldh a, [$58]
    ld hl, sp+$3c
    db $ec
    ld e, h
    db $f4
    ld a, [hl]
    ld [$d7fd], a
    xor d
    rst $38
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

jr_019_772f:
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
    ld d, l
    xor d
    xor d
    ld d, l
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
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl
    rlca
    ld sp, hl

jr_019_775f:
    rlca
    xor e
    inc bc
    ld e, l
    inc e
    cp [hl]
    ld l, b
    ld a, l
    jr nz, jr_019_775f

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
    jr c, jr_019_77d4

    jr z, jr_019_772f

    ld e, h
    ld b, l
    db $fc
    xor h
    ld a, [hl]
    ld d, a
    cp $00
    nop
    inc a
    inc a
    ld a, a
    ld a, a
    add b
    rst $38
    add b
    add b
    add b
    sub d
    add b
    sbc d
    add b
    add b
    nop
    nop
    inc a
    inc a
    cp $fe
    ld bc, $01ff
    ld bc, $d901
    ld bc, $01d1
    ld bc, $ffff
    xor d
    ld a, [$baea]
    xor d
    ld a, [$faaf]
    xor a
    rst $38
    xor d
    push af
    xor l
    ld a, [$ffff]
    ld d, l
    ld e, a
    ld d, l
    ld e, a
    ld d, l
    ld e, a
    push af
    ld e, a
    rst $30
    db $fd
    and l
    ld e, a
    ld d, l
    cp a
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
    ld d, l
    xor d
    rst $38
    rst $38
    xor d
    rst $38
    rst $38
    nop

jr_019_77d4:
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
    ld bc, $3601
    ld [hl], $7a
    ld c, [hl]
    ld sp, $142f
    rra
    ld [hl+], a
    dec sp
    ld h, b
    ld a, a
    ld e, h
    ld e, [hl]
    db $eb
    nop
    sub [hl]
    ld b, c
    xor a
    nop
    rst $18
    nop
    ld a, d
    add l
    push af
    ld a, [bc]
    ld a, [$bf05]
    ld b, b
    add b
    add b

jr_019_7812:
    ld l, h
    ld l, h
    ld d, [hl]
    ld a, d
    adc h
    db $f4
    jr z, jr_019_7812

    ld b, h
    call c, $fe06
    cp d
    ld a, d
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
    call c, $c0ff
    cp a
    and b
    sub l
    sbc a
    sbc [hl]
    add c
    sbc a
    add b
    sbc $c1
    rst $38
    and b
    rst $38
    sbc a
    rst $38
    inc bc
    db $fd
    rlca
    ld d, c
    rst $38
    cp c
    ld b, a
    ld a, c
    add a
    xor e
    ld d, a
    ld d, l
    xor a
    ld sp, hl
    rst $38
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
    ldh a, [$80]
    sbc d
    add b
    sbc d
    add b
    add b
    ld a, a
    ld a, a
    inc a
    inc h
    inc h
    rst $20
    jr @+$01

    nop
    nop
    ld bc, $0129
    xor c
    ld bc, $fe01
    cp $3c
    inc h
    inc h
    rst $20
    jr @+$01

    nop
    nop
    and b
    rst $38
    xor c
    cp $a2
    db $fd
    and l
    ld a, [$fda2]
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    dec b
    rst $38
    dec d
    rst $38
    and l
    ld e, a
    ld b, l
    cp a
    add l
    ld a, a
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    and a
    add [hl]
    sbc l
    add e
    dec b
    inc bc
    add c
    rrca
    ld d, l
    cp a
    xor e
    ld a, a
    sub $ff
    ld a, l
    ld a, b
    nop
    ld bc, $0203
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
    add b
    add b
    xor d
    add b
    sub c
    add b
    and b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    rst $38
    rst $38
    ld bc, $8901
    ld bc, $0155
    add hl, hl
    ld bc, $0115
    ld bc, $0101
    ld bc, $f082
    add b
    db $fc
    xor e
    rst $38
    ld [hl], l
    ld a, a
    cp e
    rra
    ld e, a
    ld c, $ab
    ld bc, $0055
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp e
    xor a
    ld d, a
    rst $18
    ld a, a
    xor $7f
    push af
    ccf

jr_019_7939:
    ld [$f75d], a
    ld a, a
    db $eb
    db $fd
    rst $10
    rst $38
    add c
    cp $b6
    ld a, [$f1ce]
    xor a
    db $f4
    sbc a
    ld [c], a
    cp e
    ldh [rIE], a
    call c, $ffde
    add c
    ld a, a
    ld l, l
    ld d, a
    ld a, e
    adc a
    push af
    cpl
    ld sp, hl
    ld b, a
    db $dd
    rlca
    rst $38
    cp e
    ld a, e
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
    xor e
    sbc e
    call nc, $f3fc
    cp a
    ret nc

    ld hl, sp-$28
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
    ccf
    rst $08
    db $fd
    dec bc
    rra
    dec de
    dec e
    scf
    dec a
    rst $00
    push de
    ccf
    ld sp, hl
    cp $0f
    pop af
    inc sp
    db $fc
    ld b, b
    or h
    ret c

    and h
    rst $20
    and c
    pop hl
    pop bc
    ret nz

    pop bc
    ld b, b
    or $68
    sbc b
    sbc l
    ld b, $1c
    dec d
    ld l, h
    ld d, $8c
    jr z, jr_019_7939

    ld a, [hl]
    ld a, h
    ld b, l
    ld b, h
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
    ld bc, $c0ff
    cp a
    and b
    sbc a
    adc a
    sbc b
    adc b
    sbc b
    adc b
    rst $18
    rst $08
    ccf
    ldh [$1f], a
    rst $38
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
    rst $30
    db $fc
    rlca
    ld hl, sp-$01
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
    jp Jump_019_667e


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
    db $fc
    db $eb
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
    xor d
    ld d, l
    push de
    xor e
    ld b, h
    ld e, [hl]
    sbc a
    daa
    ld e, a
    cp a
    ccf
    ld e, a
    ld a, a
    cp a
    ccf
    rst $38
    rst $38
    rst $38
    push de
    xor e
    ld b, h
    ld e, [hl]
    ld hl, sp-$1b
    db $fd
    ld a, [$fbfc]
    db $fc
    rst $38
    rst $38
    rst $38
    rst $38
    db $fd
    rst $38
    cp a
    ld a, a
    ld a, a
    cp a
    ccf

jr_019_7aa6:
    ld a, a
    cp a
    ccf
    ld a, a
    ld a, d
    cp a
    dec [hl]
    rst $18
    ld a, [$fdcf]
    rst $38
    db $fc
    cp $fc
    db $fd
    db $fd
    cp $fc
    rst $38
    xor h
    rst $38
    ld d, a
    ei
    xor a
    ld sp, hl
    ld a, [hl]
    add c
    cp l
    ld b, d
    db $db
    inc h
    rst $20
    jr @-$17

    jr jr_019_7aa6

    inc h
    cp l
    ld b, d
    ld a, [hl]
    add c
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    db $db
    inc h
    cp l
    ld b, d
    ld a, [hl]
    add c
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
    nop
    rst $38
    rst $38
    rst $38
    rrca

jr_019_7af1:
    rrca
    jr @+$1a

    jr @+$1a

    jr @+$1a

    rra
    jr jr_019_7b13

    jr jr_019_7b15

    jr jr_019_7b17

    jr jr_019_7af1

jr_019_7b01:
    ldh a, [rNR23]
    jr jr_019_7b1d

    jr jr_019_7b1f

    jr jr_019_7b01

    jr @+$1a

    jr @+$1a

    jr @+$1a

    jr jr_019_7b30

    jr @+$1a

jr_019_7b13:
    jr @+$1a

jr_019_7b15:
    jr @+$1a

jr_019_7b17:
    jr jr_019_7b38

    jr jr_019_7b3a

    rra
    rra

jr_019_7b1d:
    db $10
    rra

jr_019_7b1f:
    rra
    ld hl, sp+$18
    jr jr_019_7b3c

    jr jr_019_7b3e

    jr jr_019_7b40

    ld hl, sp+$18
    ld hl, sp-$08
    ld hl, sp+$08
    ld hl, sp-$08

jr_019_7b30:
    jr jr_019_7b4a

    jr jr_019_7b4c

    jr jr_019_7b4e

    jr @+$1a

jr_019_7b38:
    jr jr_019_7b52

jr_019_7b3a:
    jr jr_019_7b54

jr_019_7b3c:
    jr jr_019_7b56

jr_019_7b3e:
    jr jr_019_7b58

jr_019_7b40:
    nop
    nop
    nop
    ld b, h
    nop
    xor d
    ld l, h
    sub d
    inc [hl]
    ld c, d

jr_019_7b4a:
    or l
    ld c, d

jr_019_7b4c:
    db $d3
    inc l

jr_019_7b4e:
    ld h, [hl]
    jr jr_019_7b51

jr_019_7b51:
    nop

jr_019_7b52:
    nop
    nop

jr_019_7b54:
    nop
    nop

jr_019_7b56:
    nop
    nop

jr_019_7b58:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc hl
    inc hl
    inc hl
    inc hl
    dec l
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    dec l
    inc hl
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld [hl+], a
    dec e
    ld [hl+], a
    dec e
    ld a, [hl+]
    dec hl
    ld a, [hl+]
    dec hl
    ld [hl+], a
    dec e
    ld [hl+], a
    dec e
    ld bc, $0201
    dec l
    ld de, $2411
    ld [bc], a
    ld de, $2411
    inc h
    ld de, $2411
    inc h
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
    daa
    daa
    ld de, $2711
    daa
    ld de, $2711
    daa
    ld de, $2711
    daa
    ld de, $1111
    ld de, $2424
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    inc hl
    ld e, $01
    ld bc, $271e
    ld de, $2711
    daa
    ld de, $2711
    daa
    ld de, $2d11
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    add hl, bc
    ld a, [bc]
    dec l
    dec l
    add hl, de
    ld a, [de]
    ld de, $1111
    ld de, $1111
    ld de, $3711
    scf
    scf
    scf
    scf
    scf
    scf
    scf
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    ld bc, $0101
    ld bc, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $2727
    ld de, $2711
    daa
    ld de, $2711
    ld [hl], $37
    scf
    ld [hl], $37
    scf
    scf
    ld de, $2411
    inc h
    ld de, $2411
    inc h
    scf
    scf
    inc [hl]
    inc h
    scf
    scf
    scf
    inc [hl]
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    dec l
    rlca
    ld [$0807], sp
    rla
    jr jr_019_7c5e

    jr @+$09

    ld [$0807], sp
    rla
    jr jr_019_7c66

    jr jr_019_7c84

    inc sp
    inc sp
    inc sp
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d

jr_019_7c5e:
    inc d
    inc d
    inc sp
    inc sp
    inc sp
    inc sp
    inc d
    inc d

jr_019_7c66:
    inc d
    rra
    inc d
    inc d
    inc d
    rra
    inc d
    inc d
    inc d
    rra
    inc sp
    inc sp
    inc sp
    inc sp
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
    inc l
    inc l
    ld a, [hl+]
    dec hl

jr_019_7c84:
    inc l
    inc l
    ld [hl+], a
    dec e
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld [hl+], a
    dec e
    inc d
    inc d
    inc d
    rra
    inc d
    inc d
    inc d
    rra
    inc d
    inc d
    inc d
    rra
    inc d
    inc d
    inc d
    rra
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld [hl-], a
    inc d
    inc d
    inc d
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld [hl+], a
    dec e
    inc l
    inc l
    ld a, [hl+]
    dec hl
    inc l
    inc l
    ld [hl+], a
    dec e
    inc l
    inc l
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    dec h
    ld h, $03
    inc bc
    jr z, @+$2b

    dec c
    dec c
    inc hl
    inc hl
    rlca
    ld [$232d], sp
    rla
    jr @+$25

    dec l
    inc l
    inc l
    inc hl
    inc hl
    inc l
    inc l
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    dec c
    dec c
    dec c
    dec c
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    dec h
    ld h, $0d
    dec c
    jr z, jr_019_7d39

    dec d
    ld d, $0f
    rrca
    dec b
    ld b, $0f
    rrca
    dec b
    ld b, $0f
    rrca
    dec d
    ld d, $0e
    ld c, $0f
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    dec bc
    inc c
    ld c, $0e
    dec de
    inc e
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    dec bc

jr_019_7d39:
    inc c
    rrca
    rrca
    dec de
    inc e
    ld c, $0e
    rrca
    rrca
    dec d
    ld d, $0f
    rrca
    dec b
    ld b, $0f
    rrca
    dec b
    ld b, $0e
    ld c, $15
    ld d, $07
    ld [$2323], sp
    rla
    jr @+$2f

    inc hl
    inc l
    inc l
    inc hl
    dec l
    inc l
    inc l
    inc hl
    inc hl
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    jr nz, jr_019_7d8f

    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    jr nz, jr_019_7da1

    inc l
    inc l
    rlca
    ld [$2c2c], sp
    rla
    jr @+$2e

    inc l
    rlca
    ld [$2c2c], sp
    rla

jr_019_7d8f:
    jr jr_019_7d98

    ld [$2c2c], sp
    rla
    jr jr_019_7dc3

    inc l

jr_019_7d98:
    rlca
    ld [$2c2c], sp
    rla
    jr jr_019_7dcb

    inc l
    inc hl

jr_019_7da1:
    inc hl
    db $10
    ld [de], a
    dec l
    inc hl
    jr z, jr_019_7dd1

    inc hl
    dec l
    dec d
    ld d, $23
    inc hl
    jr nc, jr_019_7de1

    db $10
    ld [de], a
    inc hl
    inc hl
    jr z, @+$2b

    dec l
    inc hl
    dec d
    ld d, $23
    dec l
    jr nc, jr_019_7def

    inc hl
    inc hl
    rrca
    rrca
    rrca

jr_019_7dc3:
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca

jr_019_7dcb:
    rrca
    ld c, $0e
    ld c, $0e
    dec c

jr_019_7dd1:
    dec c
    dec c
    dec c
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld c, $0e
    ld c, $0e
    inc hl

jr_019_7de1:
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    jr nz, jr_019_7e0b

    inc hl
    inc hl
    ld l, $2f
    inc hl

jr_019_7def:
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    jr nz, @+$23

    inc hl
    inc hl
    ld l, $2f
    dec c
    dec c
    dec d
    ld d, $0f
    rrca
    dec b
    ld b, $0f
    rrca
    dec b

jr_019_7e0b:
    ld b, $0e
    ld c, $30
    ld sp, $1615
    dec c
    dec c
    dec b
    ld b, $0f
    rrca
    dec b
    ld b, $0f
    rrca
    jr nc, @+$33

    ld c, $0e
    ld de, $1111
    ld de, $1111
    ld de, $3911
    ld a, [hl-]
    scf
    scf
    dec sp
    inc a
    scf
    scf
    ld de, $1111
    ld de, $1111
    ld de, $3711
    inc de
    ld de, $1311
    daa
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $1111
    ld de, $3735
    ld de, $2411
    dec [hl]
    rlca
    ld [$2c2c], sp
    rla
    jr jr_019_7e93

    inc l
    rlca
    ld [$2c2c], sp
    rla
    jr @+$2e

    inc l
    inc l
    inc l
    rlca
    ld [$2c2c], sp
    rla
    jr @+$2e

    inc l
    rlca
    ld [$2c2c], sp
    rla
    jr @+$09

    ld [$0807], sp
    rla
    jr @+$19

    jr jr_019_7eb5

    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l

jr_019_7e93:
    inc l
    inc l
    inc l
    inc l
    inc l
    rlca
    ld [$0807], sp
    rla
    jr jr_019_7eb6

    jr jr_019_7ecf

    cpl
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    inc bc
    inc bc
    ld l, $2f
    inc bc

jr_019_7eb5:
    inc bc

jr_019_7eb6:
    ld l, $2f
    inc bc
    inc bc
    ld l, $2f
    inc bc
    inc bc
    ld l, $2f
    ld [hl-], a
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

jr_019_7ecf:
    inc d
    inc d
    inc d
    inc d
    rra
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
    dec [hl]
    scf
    scf
    scf
    inc h
    dec [hl]
    scf
    scf
    inc h
    inc h
    ld de, $2411
    inc h
    ld de, $4011
    ld a, $3e
    ld a, $44
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld a, $3e
    ld a, $41
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    ld a, $3e
    ld a, $3e
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    dec a
    dec a
    dec a
    ld b, h
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    inc l
    inc hl
    inc l
    inc hl
    inc hl
    inc l
    inc hl
    inc l
    inc l
    inc hl
    inc l
    inc hl
    inc hl
    inc l
    inc hl
    inc l
    inc l
    inc hl
    db $10
    ld [de], a
    inc hl
    inc l
    jr z, jr_019_7fa1

    inc l
    inc hl
    dec d
    ld d, $23
    inc l
    jr nc, jr_019_7fb1

    db $10
    ld [de], a
    inc l
    inc hl
    jr z, @+$2b

    inc hl
    inc l
    dec d
    ld d, $2c
    inc hl
    jr nc, jr_019_7fbf

    inc hl
    inc l
    rlca
    ld [$2c2c], sp
    rla
    jr jr_019_7fc3

    inc l
    jr nz, jr_019_7fbb

    inc l
    inc l
    ld l, $2f
    inc l
    inc l
    inc l

jr_019_7fa1:
    inc l
    rlca
    ld [$2c2c], sp
    rla
    jr jr_019_7fd5

    inc l
    jr nz, jr_019_7fcd

    inc l
    inc l
    ld l, $2f
    inc d

jr_019_7fb1:
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    jr nz, jr_019_7fdb

    inc d

jr_019_7fbb:
    inc d
    ld l, $2f

Jump_019_7fbe:
    inc d

jr_019_7fbf:
    inc d
    inc d
    inc d
    inc d

jr_019_7fc3:
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    inc d
    jr nz, jr_019_7fed

    inc d

jr_019_7fcd:
    inc d
    ld l, $2f
    inc l
    inc l
    inc l
    inc l
    inc l

jr_019_7fd5:
    inc l
    inc l
    inc l
    inc l
    inc l
    add hl, bc

jr_019_7fdb:
    ld a, [bc]
    inc l
    inc l
    add hl, de
    ld a, [de]
    adc h
    db $d3
    dec c
    rlca
    and e
    sbc e
    ld l, a
    and b
    ld h, e
    rst $08
    scf
    rst $00
    dec h

jr_019_7fed:
    rlca
    ret


    push hl
    add sp, $55
    ld c, a
    xor l
    ld [$2249], sp
    sbc e
    ld h, e
    sbc e
    adc e
    res 5, a
    adc a
    db $c3
    db $ee
