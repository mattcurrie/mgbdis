; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $000", ROM0[$0]

RST_00::
    pop af

Call_000_0001:
    call Call_000_0961
    call Call_000_0017
    db $fa

RST_08::
    nop
    rst $18
    cp $02
    jr nz, jr_000_0016

Call_000_000e:
    ld a, d
    db $fe

RST_10::
    ld b, b

Call_000_0011:
    jr c, jr_000_0016

Call_000_0013:
    call RST_30

Jump_000_0016:
jr_000_0016:
    ret


Call_000_0017:
    push hl

RST_18::
    jp Jump_000_0406


    nop
    nop
    nop
    nop
    nop

RST_20::
    push af
    xor a
    ld [$6000], a
    ld a, $20
    db $ea

RST_28::
    nop
    ld h, b
    pop af
    jp Jump_000_0150


    nop
    nop

RST_30::
    xor a
    ld [$df00], a
    ld a, [$df02]
    db $e0

RST_38::
    cp b
    ld [$2000], a

Jump_000_003c:
    ret


    nop
    nop
    nop

VBlankInterrupt::
    jp Jump_000_0aac


Call_000_0043:
    ld a, $0a

Jump_000_0045:
    ld [$0000], a

LCDCInterrupt::
    xor a
    ld [$4000], a
    ei
    ret


    nop
    nop

TimerOverflowInterrupt::
    jp Jump_000_0d9a


    nop
    nop

Call_000_0055:
    nop
    nop

Call_000_0057:
Jump_000_0057:
    nop

SerialTransferCompleteInterrupt::
    jp Jump_000_0ba7 ; → SerialISR ($0BA7)


    nop
    nop
    nop
    nop
    nop

JoypadTransitionInterrupt::
    reti


    nop

Jump_000_0062:
    nop
    nop
    nop
    nop
    nop
    nop

Call_000_0068:
    rst $38
    rst $18
    dec a
    ld e, l
    di
    scf
    db $fd

Call_000_006f:
    ld [hl], c

Call_000_0070:
    push af
    cp a
    ld d, a

Call_000_0073:
    db $fd
    sub a
    db $76

Call_000_0076:
    cp e

Call_000_0077:
    reti


Call_000_0078:
    rst $18
    rst $18
    rst $38
    reti


    rst $38
    rst $38
    reti


Call_000_007f:
    sbc a
    ld a, [hl]
    cp $ed
    jr nz, jr_000_00a4

    ld a, $01
    ld [$df00], a
    inc hl
    ld a, [hl+]
    ld [$df01], a
    ld a, [hl+]
    push af
    ld a, [hl]
    push af
    pop af
    ld h, a
    pop af
    ld l, a
    ldh a, [$b8]
    ld [$df02], a
    ld a, [$df01]
    ldh [$b8], a
    ld [$2000], a

jr_000_00a4:
    jp Jump_000_0602


Call_000_00a7:
    di
    ld [$2000], a
    call $4000
    ret


    nop
    nop
    nop

Call_000_00b2:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_000_00c2:
    nop

Call_000_00c3:
    nop
    nop
    rst $18

Call_000_00c6:
    ld a, [hl]
    cp $ed
    jr nz, jr_000_00dc

    inc hl

Call_000_00cc:
    ld a, [hl+]

Call_000_00cd:
    push af
    ld a, [hl+]
    push af
    ld a, [hl]
    push af

Jump_000_00d2:
    pop af
    ld h, a

Call_000_00d4:
    pop af
    ld l, a
    pop af
    ldh [$b8], a
    ld [$2000], a

jr_000_00dc:
    ld a, [$d092]
    ret


    or b
    and e
    ld d, b
    rst $38
    or b
    and l
    or h
    ld d, b
    xor l
    xor c
    or e

Jump_000_00eb:
    or e

Call_000_00ec:
    xor c

Call_000_00ed:
Jump_000_00ed:
    xor h

Jump_000_00ee:
    and l
    ld d, b
    or e
    push bc

Jump_000_00f2:
    jp $c5d2


    call nc, $c1ad
    jp $c9c8


    adc $c5
    rst $38

Call_000_00fe:
Jump_000_00fe:
    rst $38

Call_000_00ff:
    rst $38

Boot::
    nop

Jump_000_0101:
    jp RST_20


HeaderLogo::
    db $ce, $ed, $66, $66, $cc, $0d, $00, $0b, $03, $73, $00, $83, $00, $0c, $00, $0d
    db $00, $08, $11, $1f, $88, $89, $00, $0e, $dc, $cc, $6e, $e6, $dd, $dd, $d9, $99
    db $bb, $bb, $67, $63, $6e, $0e, $ec, $cc, $dd, $dc, $99, $9f, $bb, $b9, $33, $3e

HeaderTitle::
    db "POKEMON GREEN", $00, $00, $00

HeaderNewLicenseeCode::
    db $30, $31

HeaderSGBFlag::
    db $03

HeaderCartridgeType::
    db $1b

HeaderROMSize::
    db $05

HeaderRAMSize::
    db $03

HeaderDestinationCode::
    db $00

HeaderOldLicenseeCode::
    db $33

HeaderMaskROMVersion::
    db $00

HeaderComplementCheck::
    db $83

HeaderGlobalChecksum::
    db $f5, $7e

Call_000_0150:
Jump_000_0150:
    jp Jump_000_09da


Call_000_0153:
Jump_000_0153:
    ldh a, [$b8]
    push af

Jump_000_0156:
    ld a, $03
    ldh [$b8], a
    call Call_000_00a7
    call Call_000_0043
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_0167:
    xor a
    ldh [rIF], a
    ldh a, [rIE]
    ld b, a
    res 0, a
    ldh [rIE], a

jr_000_0171:
    ldh a, [rLY]
    cp $91
    jr nz, jr_000_0171

    ldh a, [rLCDC]
    and $7f
    ldh [rLCDC], a
    ld a, b
    ldh [rIE], a
    ret


Call_000_0181:
Jump_000_0181:
    ldh a, [rLCDC]
    set 7, a
    ldh [rLCDC], a
    ret


Call_000_0188:
Jump_000_0188:
    xor a
    ld hl, $c300
    ld b, $a0

jr_000_018e:
    ld [hl+], a
    dec b
    jr nz, jr_000_018e

    ret


Call_000_0193:
Jump_000_0193:
    ld a, $a0
    ld hl, $c300
    ld de, $0004
    ld b, $28

jr_000_019d:
    ld [hl], a
    add hl, de
    dec b
    jr nz, jr_000_019d

    ret


Call_000_01a3:
    ld [$cee4], a
    ldh a, [$b8]
    push af
    ld a, [$cee4]
    ldh [$b8], a
    ld [$2000], a
    call Call_000_01bb
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_01bb:
Jump_000_01bb:
jr_000_01bb:
    ld a, [hl+]
    ld [de], a
    inc de
    dec bc
    ld a, c
    or b
    jr nz, jr_000_01bb

Jump_000_01c3:
    ret


    dec bc
    inc c
    inc de
    dec d
    jr @+$01

    nop
    db $10
    dec de
    jr nz, @+$23

    inc hl
    inc l
    dec l
    ld l, $30
    ld sp, $3933
    inc a
    ld a, $52
    ld d, h
    ld e, b
    ld e, e
    rst $38
    ld bc, $0302
    ld de, $1312
    inc d
    inc e
    ld a, [de]
    rst $38
    ld de, $1c1a
    inc a
    ld e, [hl]

Jump_000_01ed:
    rst $38
    ld de, $1916
    dec hl
    inc a
    dec a
    ccf
    ld c, d
    ld c, h
    ld c, l
    inc bc
    rst $38
    ld e, $20
    ld l, $30
    inc [hl]
    scf

Jump_000_0200:
    add hl, sp
    ld a, [hl-]
    ld b, b
    ld d, c
    ld d, d

Jump_000_0205:
    ld e, d
    ld e, h
    ld e, [hl]

Jump_000_0208:
    ld e, a
    rst $38
    ld bc, $1412
    jr z, jr_000_0241

    scf
    ld b, h
    ld d, h
    ld e, h
    rst $38
    ld bc, $1412
    ld a, [de]
    inc e
    scf
    jr c, @+$3d

    inc a

Jump_000_021d:
    ld e, [hl]
    rst $38

Call_000_021f:
    inc b
    dec c

Call_000_0221:
    rla
    dec e
    ld e, $23
    inc [hl]
    scf

Call_000_0227:
    add hl, sp
    ld c, d
    rst $38
    ld a, [bc]
    ld a, [de]
    ld [hl-], a
    dec sp
    rst $38
    ld bc, $1310
    dec de
    ld [hl+], a
    ld b, d
    ld d, d
    rst $38
    inc b
    rrca
    dec d
    rra
    dec sp
    ld b, l
    ld b, a
    ld d, l
    ld d, [hl]
    rst $38

jr_000_0241:
    dec b
    dec d
    jr jr_000_025f

    jr nz, jr_000_0268

    ld [hl+], a
    ld a, [hl+]
    dec l
    jr nc, @+$01

    rst $38
    inc d
    rla
    ld a, [de]
    inc e
    jr nz, jr_000_028b

    ld b, l
    rst $38

Call_000_0255:
    ld bc, $1105
    ld [de], a
    inc d
    ld a, [de]
    inc e
    inc l
    ld d, e
    rst $38

jr_000_025f:
    inc c
    ld h, $16
    ld e, $34
    scf
    rst $38
    rrca
    ld a, [de]

jr_000_0268:
    rra
    ld h, $28
    add hl, hl
    inc l
    dec l
    ld l, $2f
    ld b, c
    rst $38
    ld bc, $1110
    inc de
    dec de
    jr nz, @+$23

    ld [hl+], a
    jr nc, @+$33

    ld [hl-], a
    ld b, d
    ld b, e
    ld c, b
    ld d, d
    ld d, l
    ld e, b
    ld e, [hl]
    rst $38
    dec de
    inc hl
    inc l
    dec l
    dec sp
    ld b, l

jr_000_028b:
    rst $38

Call_000_028c:
Jump_000_028c:
    ldh [$8b], a
    ldh a, [$b8]
    push af
    ldh a, [$8b]
    ldh [$b8], a
    ld [$2000], a
    call Call_000_01bb
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


    ldh [$8b], a
    ldh a, [$b8]
    push af
    ldh a, [$8b]
    ldh [$b8], a
    ld [$2000], a
    push hl
    push de

Call_000_02b0:
Jump_000_02b0:
    push de
    ld d, h
    ld e, l
    pop hl
    call Call_000_01bb
    pop de
    pop hl
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_02c0:
Jump_000_02c0:
    ldh [$8b], a
    ldh a, [$b8]
    push af
    ldh a, [$8b]
    ldh [$b8], a
    ld [$2000], a

jr_000_02cc:
    ld a, [hl+]
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec bc
    ld a, c
    or b
    jr nz, jr_000_02cc

    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_02dd:
Jump_000_02dd:
    ldh a, [$ba]
    push af
    xor a
    ldh [$ba], a
    ldh a, [$b8]
    ldh [$8b], a
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ld a, e
    ldh [$c7], a
    ld a, d
    ldh [$c8], a
    ld a, l
    ldh [$c9], a
    ld a, h
    ldh [$ca], a

jr_000_02f9:
    ld a, c
    cp $08

Call_000_02fc:
    jr nc, jr_000_030e

    ldh [$c6], a
    call Call_000_0b31

Call_000_0303:
    ldh a, [$8b]
    ldh [$b8], a
    ld [$2000], a
    pop af
    ldh [$ba], a
    ret


jr_000_030e:
    ld a, $08
    ldh [$c6], a
    call Call_000_0b31
    ld a, c
    sub $08
    ld c, a
    jr jr_000_02f9

Call_000_031b:
Jump_000_031b:
    ldh a, [$ba]
    push af
    xor a
    ldh [$ba], a
    ldh a, [$b8]
    ldh [$8b], a
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ld a, e
    ldh [$cc], a
    ld a, d
    ldh [$cd], a
    ld a, l
    ldh [$ce], a
    ld a, h
    ldh [$cf], a

jr_000_0337:
    ld a, c
    cp $08
    jr nc, jr_000_034c

    ldh [$cb], a
    call Call_000_0b31
    ldh a, [$8b]
    ldh [$b8], a
    ld [$2000], a
    pop af
    ldh [$ba], a
    ret


jr_000_034c:
    ld a, $08
    ldh [$cb], a

Call_000_0350:
    call Call_000_0b31

Jump_000_0353:
    ld a, c
    sub $08
    ld c, a

Call_000_0357:
    jr jr_000_0337

Call_000_0359:
Jump_000_0359:
jr_000_0359:
    call Call_000_0b31
    push bc
    call Call_000_3879
    pop bc

Call_000_0361:
    ldh a, [$b4]

Call_000_0363:
    cp $46

Call_000_0365:
    jr z, jr_000_0372

    ldh a, [$b5]
    and $09
    jr nz, jr_000_0372

Jump_000_036d:
    dec c
    jr nz, jr_000_0359

    and a
    ret


jr_000_0372:
    scf
    ret


Call_000_0374:
Jump_000_0374:
    ld a, $7f
    ld de, $0014

jr_000_0379:
    push hl
    push bc

jr_000_037b:
    ld [hl+], a
    dec c
    jr nz, jr_000_037b

    pop bc
    pop hl
    add hl, de
    dec b

Jump_000_0383:
    jr nz, jr_000_0379

    ret


Call_000_0386:
    ld c, $06
    ld hl, $0000
    ld de, $c3a0
    call Call_000_03ac
    call Call_000_0b31
    ld hl, $0600
    ld de, $c418
    call Call_000_03ac
    call Call_000_0b31
    ld hl, $0c00
    ld de, $c490
    call Call_000_03ac
    jp Jump_000_0b31


Call_000_03ac:
    ld a, d
    ldh [$c2], a
    call $0774

Jump_000_03b2:
    ld a, l
    ldh [$c3], a
    ld a, h
    ldh [$c4], a
    ld a, c
    ldh [$c5], a
    ld a, e
    ldh [$c1], a
    ret


Call_000_03bf:
Jump_000_03bf:
    ld bc, $0168
    inc b

Jump_000_03c3:
    ld hl, $c3a0
    ld a, $7f

jr_000_03c8:
    ld [hl+], a
    dec c
    jr nz, jr_000_03c8

    dec b
    jr nz, jr_000_03c8

    jp Jump_000_3e07


Call_000_03d2:
    push hl
    ld a, $79
    ld [hl+], a
    inc a
    call Call_000_03ff
    inc a
    ld [hl], a
    pop hl
    ld de, $0014
    add hl, de

Jump_000_03e1:
jr_000_03e1:
    push hl
    ld a, $7c
    ld [hl+], a
    ld a, $7f
    call Call_000_03ff
    ld [hl], $7c

Jump_000_03ec:
    pop hl
    ld de, $0014
    add hl, de
    dec b
    jr nz, jr_000_03e1

    ld a, $7d
    ld [hl+], a
    ld a, $7a
    call Call_000_03ff
    ld [hl], $7e
    ret


Call_000_03ff:
    ld d, c

Call_000_0400:
Jump_000_0400:
jr_000_0400:
    ld [hl+], a

Jump_000_0401:
    dec d

Call_000_0402:
    jr nz, jr_000_0400

Jump_000_0404:
    ret


Call_000_0405:
Jump_000_0405:
    rst $00

Jump_000_0406:
    ld a, [de]

Jump_000_0407:
    cp $50

Jump_000_0409:
    jr nz, jr_000_040f

    ld b, h
    ld c, l
    pop hl
    ret


jr_000_040f:
    cp $4e
    jr nz, jr_000_041c

    pop hl
    ld bc, $0028
    add hl, bc
    push hl
    jp Jump_000_04c5


jr_000_041c:
    cp $4f
    jr nz, jr_000_0428

    pop hl
    ld hl, $c4e1
    push hl
    jp Jump_000_04c5


jr_000_0428:
    and a

Jump_000_0429:
    jp z, Jump_000_04c9

    cp $4c
    jp z, Jump_000_05bb

    cp $4b
    jp z, Jump_000_05a9

    cp $51

Jump_000_0438:
    jp z, Jump_000_0588

    cp $52

Call_000_043d:
    jp z, Jump_000_04da

    cp $53
    jp z, Jump_000_04e0

Call_000_0445:
    cp $54
    jp z, Jump_000_04fe

    cp $5b
    jp z, Jump_000_04f2

    cp $5e
    jp z, Jump_000_04f8

    cp $5c
    jp z, Jump_000_04ec

    cp $5d
    jp z, Jump_000_04e6

    cp $55
    jp z, Jump_000_0555

    cp $56
    jp z, Jump_000_0504

    cp $57
    jp z, Jump_000_0581

    cp $58
    jp z, Jump_000_0569

    cp $59

Jump_000_0474:
    jp z, Jump_000_050a

    cp $5a
    jp z, Jump_000_0510

    cp $e4
    jr z, jr_000_0484

    cp $e5

Jump_000_0482:
    jr nz, jr_000_048d

jr_000_0484:
    pop hl
    ld bc, $0014
    add hl, bc
    push hl
    jp Jump_000_04c5


jr_000_048d:
    cp $ec
    jr nz, jr_000_04c1

    inc de
    ld a, [de]
    push af
    inc de
    ld a, [de]
    ld d, a

Jump_000_0497:
    pop af
    ld e, a
    jr jr_000_04c6

    jr jr_000_049f

    add $90

jr_000_049f:
    push af
    and [hl]
    xor a
    and l
    ld a, a
    ld d, b
    rst $38
    add hl, bc
    ld [hl], a
    or h
    or d
    and c
    xor c

Call_000_04ac:
    xor [hl]

Jump_000_04ad:
    and l
    or d
    ld d, b
    or e
    xor e
    xor c
    xor h
    xor h
    ld a, a
    xor l
    and c
    and e
    xor b
    xor c
    xor [hl]
    and l

Call_000_04bd:
    ld d, b
    ld [hl], a
    pop hl
    pop af

jr_000_04c1:
    ld [hl+], a
    call Call_000_391d

Jump_000_04c5:
    inc de

jr_000_04c6:
    jp Jump_000_0406


Jump_000_04c9:
    ld b, h
    ld c, l
    pop hl
    ld de, $04d1
    dec de
    ret


    add hl, bc
    adc h
    rst $38
    ld [de], a
    nop
    add e
    and l
    db $e3
    ld d, a

Jump_000_04da:
    push de
    ld de, $d11d
    jr jr_000_0526

Call_000_04e0:
Jump_000_04e0:
    push de
    ld de, $d2ce
    jr jr_000_0526

Jump_000_04e6:
    push de
    ld de, $0536
    jr jr_000_0526

Jump_000_04ec:
    push de

Jump_000_04ed:
    ld de, $0530
    jr jr_000_0526

Jump_000_04f2:
    push de
    ld de, $053c
    jr jr_000_0526

Jump_000_04f8:
    push de
    ld de, $0541
    jr jr_000_0526

Jump_000_04fe:
    push de
    ld de, $0548
    jr jr_000_0526

Jump_000_0504:
    push de

Call_000_0505:
    ld de, $054d
    jr jr_000_0526

Jump_000_050a:
    ldh a, [$f3]
    xor $01
    jr jr_000_0512

Jump_000_0510:
    ldh a, [$f3]

jr_000_0512:
    push de
    and a
    jr nz, jr_000_051b

    ld de, $cff0
    jr jr_000_0526

jr_000_051b:
    ld de, $0550
    call Call_000_0405
    ld h, b
    ld l, c
    ld de, $cfc1

jr_000_0526:
    call Call_000_0405
    ld h, b
    ld l, c
    pop de
    inc de
    jp Jump_000_0406


    db $ec
    or b
    inc b
    adc e
    xor e
    ld d, b
    db $ec
    xor b
    inc b
    sub h
    db $e3
    ld d, b
    db $ec
    ldh [rP1], a
    xor e

Jump_000_0540:
    ld d, b
    db $ec
    add sp, $00
    sub e

Call_000_0545:
    jr nc, @-$20

    ld d, b
    db $ec
    db $e4
    nop
    xor e
    ld d, b
    ld [hl], l
    ld [hl], l
    ld d, b

Call_000_0550:
    db $ec
    and b
    inc b

Call_000_0553:
Jump_000_0553:
    ld a, a
    ld d, b

Jump_000_0555:
    push de

Call_000_0556:
    ld b, h
    ld c, l
    ld hl, $0565
    call Call_000_05f1
    ld h, b
    ld l, c
    pop de
    inc de
    jp Jump_000_0406


    nop
    ld c, e
    ld d, b
    ld d, b

Jump_000_0569:
    ld a, [$d0f0]
    cp $04
    jp z, Jump_000_0576

    ld a, $ee
    ld [$c4f2], a

Jump_000_0576:
    call Call_000_05eb

Call_000_0579:
    call Call_000_38e1

Call_000_057c:
    ld a, $7f
    ld [$c4f2], a

Jump_000_0581:
    pop hl
    ld de, $0587

Call_000_0585:
    dec de
    ret


    ld d, b

Jump_000_0588:
    push de
    ld a, $ee
    ld [$c4f2], a
    call Call_000_05eb
    call Call_000_38e1
    ld hl, $c4a5
    ld bc, $0412
    call Call_000_0374
    ld c, $14
    call Call_000_3781
    pop de
    ld hl, $c4b9
    jp Jump_000_04c5


Jump_000_05a9:
    ld a, $ee
    ld [$c4f2], a
    call Call_000_05eb
    push de
    call Call_000_38e1
    pop de
    ld a, $7f
    ld [$c4f2], a

Jump_000_05bb:
    push de
    call Call_000_05c9
    call Call_000_05c9

Jump_000_05c2:
    ld hl, $c4e1
    pop de
    jp Jump_000_04c5


Call_000_05c9:
    ld hl, $c4b8
    ld de, $c4a4
    ld b, $3c

jr_000_05d1:
    ld a, [hl+]
    ld [de], a
    inc de
    dec b
    jr nz, jr_000_05d1

    ld hl, $c4e1
    ld a, $7f
    ld b, $12

Call_000_05de:
jr_000_05de:
    ld [hl+], a
    dec b

Jump_000_05e0:
    jr nz, jr_000_05de

    ld b, $05

jr_000_05e4:
    call Call_000_0b31
    dec b
    jr nz, jr_000_05e4

    ret


Call_000_05eb:
    push bc
    call Call_000_3e07
    pop bc
    ret


Call_000_05f1:
    ld a, [$d2d7]
    push af

Jump_000_05f5:
    set 1, a
    ld [$d2d7], a
    ld a, c
    ld [$cc3a], a
    ld a, b

Jump_000_05ff:
    ld [$cc3b], a

Call_000_0602:
Jump_000_0602:
jr_000_0602:
    ld a, [hl+]

Jump_000_0603:
    cp $50

Jump_000_0605:
    jr nz, jr_000_060c

    pop af

Call_000_0608:
Jump_000_0608:
    ld [$d2d7], a
    ret


jr_000_060c:
    push hl
    ld hl, $0746
    push bc
    add a
    ld b, $00
    ld c, a
    add hl, bc
    pop bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp hl


    pop hl
    ld a, [hl+]
    ld e, a
    ld a, [hl+]

Call_000_061f:
    ld d, a

Jump_000_0620:
    ld a, [hl+]
    ld b, a
    ld a, [hl+]

Jump_000_0623:
    ld c, a
    push hl
    ld h, d
    ld l, e
    call Call_000_03d2
    pop hl
    jr jr_000_0602

    pop hl
    ld d, h
    ld e, l

Jump_000_0630:
    ld h, b
    ld l, c

Call_000_0632:
    call Call_000_0405
    ld h, d
    ld l, e
    inc hl

Jump_000_0638:
    jr jr_000_0602

    pop hl
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    push hl
    ld h, b
    ld l, c
    call Call_000_0405
    pop hl
    jr jr_000_0602

    pop hl
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    push hl
    ld h, b
    ld l, c
    ld c, a

Jump_000_0652:
    call Call_000_2fc4
    ld b, h
    ld c, l
    pop hl
    jr jr_000_0602

    pop hl
    ld a, [hl+]
    ld [$cc3a], a
    ld c, a
    ld a, [hl+]
    ld [$cc3b], a
    ld b, a
    jp Jump_000_0602


    pop hl
    ld bc, $c4e1
    jp Jump_000_0602


    ld a, [$d0f0]
    cp $04
    jp z, Jump_000_073d

    ld a, $ee
    ld [$c4f2], a
    push bc
    call Call_000_38e1

Jump_000_0680:
    pop bc

Call_000_0681:
    ld a, $7f

Jump_000_0683:
    ld [$c4f2], a
    pop hl
    jp Jump_000_0602


    ld a, $7f
    ld [$c4f2], a
    call Call_000_05c9
    call Call_000_05c9
    pop hl
    ld bc, $c4e1
    jp Jump_000_0602


    pop hl
    ld de, $0080
    push de

Call_000_06a1:
    jp hl


    pop hl
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    push hl
    ld h, b
    ld l, c
    ld b, a
    and $0f
    ld c, a
    ld a, b
    and $f0

Jump_000_06b2:
    swap a
    set 6, a
    ld b, a
    call Call_000_3c8f
    ld b, h
    ld c, l
    pop hl
    jp Jump_000_0602


Jump_000_06c0:
    push bc
    call Call_000_0153
    ldh a, [$b4]
    and $03
    jr nz, jr_000_06cf

    ld c, $1e
    call Call_000_3781

jr_000_06cf:
    pop bc
    pop hl
    jp Jump_000_0602


    pop hl
    push bc
    dec hl
    ld a, [hl+]
    ld b, a
    push hl
    ld hl, $0707

jr_000_06dd:
    ld a, [hl+]

Jump_000_06de:
    cp b
    jr z, jr_000_06e4

Jump_000_06e1:
    inc hl
    jr jr_000_06dd

jr_000_06e4:
    cp $14
    jr z, jr_000_06fc

    cp $15
    jr z, jr_000_06fc

    cp $16
    jr z, jr_000_06fc

Jump_000_06f0:
    ld a, [hl]
    call Call_000_0e45
    call Call_000_3790
    pop hl
    pop bc
    jp Jump_000_0602


jr_000_06fc:
    push de
    ld a, [hl]
    call Call_000_2dc7

Call_000_0701:
Jump_000_0701:
    pop de

Call_000_0702:
    pop hl

Call_000_0703:
    pop bc

Jump_000_0704:
    jp Jump_000_0602


    dec bc

Jump_000_0708:
    add [hl]
    ld [de], a

Jump_000_070a:
    sbc d
    ld c, $91
    rrca
    add [hl]
    db $10
    adc c

Jump_000_0711:
    ld de, $1394
    sbc b
    inc d
    xor b
    dec d
    sub a
    ld d, $78
    pop hl
    ld a, [hl+]
    ld d, a
    push hl
    ld h, b
    ld l, c

Jump_000_0721:
jr_000_0721:
    ld a, $75

Call_000_0723:
    ld [hl+], a
    push de
    call Call_000_0153

Jump_000_0728:
    pop de
    ldh a, [$b4]
    and $03
    jr nz, jr_000_0734

    ld c, $0a
    call Call_000_3781

jr_000_0734:
    dec d
    jr nz, jr_000_0721

    ld b, h
    ld c, l
    pop hl
    jp Jump_000_0602


Jump_000_073d:
    push bc
    call Call_000_38e1
    pop bc
    pop hl

Call_000_0743:
    jp Jump_000_0602


    dec l
    ld b, $3a
    ld b, $48
    ld b, $5a
    ld b, $1b
    ld b, $68
    ld b, $6f
    ld b, $8a

Jump_000_0755:
    ld b, $9c
    ld b, $a2
    ld b, $c0
    ld b, $d4
    ld b, $1b
    rlca

Call_000_0760:
Jump_000_0760:
    dec a
    rlca
    call nc, $d406
    ld b, $d4

Call_000_0767:
    ld b, $d4
    ld b, $d4
    ld b, $d4
    ld b, $d4

Call_000_076f:
Jump_000_076f:
    ld b, $d4

Call_000_0771:
    ld b, $d4
    ld b, $af

Call_000_0775:
    srl h
    rr a
    srl h
    rr a
    srl h

Call_000_077f:
Jump_000_077f:
    rr a

Jump_000_0781:
    or l

Jump_000_0782:
    ld l, a
    ld a, b
    or h

Call_000_0785:
    ld h, a
    ret


Call_000_0787:
    ld a, $7f
    jr jr_000_078c

    ld a, l

jr_000_078c:
    ld de, $0400
    ld l, e

Call_000_0790:
jr_000_0790:
    ld [hl+], a
    dec e
    jr nz, jr_000_0790

    dec d
    jr nz, jr_000_0790

    ret


Call_000_0798:
    ldh a, [$d0]
    and a
    ret z

    ld b, a
    xor a
    ldh [$d0], a
    dec b
    jr nz, jr_000_07c7

    ld hl, $cbfc
    ldh a, [$d1]
    ld e, a
    ldh a, [$d2]
    ld d, a
    ld c, $12

jr_000_07ae:
    ld a, [hl+]
    ld [de], a

Call_000_07b0:
    inc de
    ld a, [hl+]
    ld [de], a
    ld a, $1f
    add e
    ld e, a

Call_000_07b7:
    jr nc, jr_000_07ba

    inc d

jr_000_07ba:
    ld a, d
    and $03

Call_000_07bd:
    or $98
    ld d, a
    dec c

Call_000_07c1:
    jr nz, jr_000_07ae

Call_000_07c3:
    xor a
    ldh [$d0], a
    ret


Call_000_07c7:
jr_000_07c7:
    ld hl, $cbfc
    ldh a, [$d1]
    ld e, a

Jump_000_07cd:
    ldh a, [$d2]
    ld d, a
    push de
    call Call_000_07d9
    pop de
    ld a, $20
    add e
    ld e, a

Call_000_07d9:
    ld c, $0a

jr_000_07db:
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    ld a, e

Jump_000_07e1:
    inc a
    and $1f
    ld b, a
    ld a, e
    and $e0
    or b
    ld e, a
    dec c
    jr nz, jr_000_07db

    ret


Call_000_07ee:
    ldh a, [$ba]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [$bf], a
    ld a, l
    ldh [$c0], a
    ldh a, [$bb]
    and a
    jr z, jr_000_0815

    dec a
    jr z, jr_000_0825

    ld hl, $c490
    ld sp, hl
    ld a, [$ffbd]
    ld h, a
    ld a, [$ffbc]
    ld l, a
    ld de, $0180
    add hl, de
    xor a
    jr jr_000_0837

jr_000_0815:
    ld hl, $c3a0
    ld sp, hl

Call_000_0819:
    ld a, [$ffbd]
    ld h, a
    ld a, [$ffbc]
    ld l, a
    ld a, $01
    jr jr_000_0837

jr_000_0825:
    ld hl, $c418
    ld sp, hl
    ld a, [$ffbd]
    ld h, a

Call_000_082d:
    ld a, [$ffbc]
    ld l, a
    ld de, $00c0
    add hl, de
    ld a, $02

jr_000_0837:
    ldh [$bb], a
    ld b, $06

jr_000_083b:
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de

Jump_000_0841:
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de

Call_000_0850:
Jump_000_0850:
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l

Call_000_0857:
Jump_000_0857:
    ld [hl], d

Call_000_0858:
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e

Call_000_086a:
    inc l
    ld [hl], d
    ld a, $0d
    add l
    ld l, a
    jr nc, jr_000_0873

    inc h

jr_000_0873:
    dec b
    jr nz, jr_000_083b

    ldh a, [$bf]
    ld h, a
    ldh a, [$c0]
    ld l, a
    ld sp, hl
    ret


Call_000_087e:
    ldh a, [$c1]
    and a
    ret z

    ld hl, sp+$00

Call_000_0884:
    ld a, h
    ldh [$bf], a
    ld a, l
    ldh [$c0], a
    ldh a, [$c1]
    ld l, a
    ldh a, [$c2]
    ld h, a
    ld sp, hl
    ldh a, [$c3]
    ld l, a
    ldh a, [$c4]
    ld h, a
    ldh a, [$c5]
    ld b, a
    xor a
    ldh [$c1], a
    jr jr_000_083b

Call_000_089f:
    ldh a, [$cb]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [$bf], a
    ld a, l
    ldh [$c0], a
    ldh a, [$cc]
    ld l, a
    ldh a, [$cd]
    ld h, a
    ld sp, hl
    ldh a, [$ce]
    ld l, a
    ldh a, [$cf]
    ld h, a
    ldh a, [$cb]
    ld b, a
    xor a
    ldh [$cb], a

jr_000_08be:
    pop de
    ld [hl], e
    inc l
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    ld [hl], d

Call_000_08c6:
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    ld [hl], d
    inc hl
    dec b
    jr nz, jr_000_08be

    ld a, l
    ldh [$ce], a
    ld a, h
    ldh [$cf], a
    ld hl, sp+$00
    ld a, l
    ldh [$cc], a
    ld a, h
    ldh [$cd], a
    ldh a, [$bf]
    ld h, a
    ldh a, [$c0]

Call_000_08f8:
    ld l, a
    ld sp, hl
    ret


Call_000_08fb:
    ldh a, [$c6]
    and a
    ret z

    ld hl, sp+$00

Jump_000_0901:
    ld a, h
    ldh [$bf], a
    ld a, l
    ldh [$c0], a
    ldh a, [$c7]
    ld l, a
    ldh a, [$c8]
    ld h, a
    ld sp, hl
    ldh a, [$c9]
    ld l, a
    ldh a, [$ca]

Jump_000_0913:
    ld h, a
    ldh a, [$c6]
    ld b, a
    xor a
    ldh [$c6], a

jr_000_091a:
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d

Jump_000_092d:
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc hl

Call_000_0942:
    dec b
    jr nz, jr_000_091a

    ld a, l
    ldh [$c9], a
    ld a, h
    ldh [$ca], a
    ld hl, sp+$00
    ld a, l
    ldh [$c7], a

Jump_000_0950:
    ld a, h
    ldh [$c8], a
    ldh a, [$bf]
    ld h, a
    ldh a, [$c0]
    ld l, a
    ld sp, hl
    ret


Call_000_095b:
    jp Jump_000_0964


Jump_000_095e:
    jp Jump_000_096f


Call_000_0961:
    jp Jump_000_09a1


Jump_000_0964:
    ld a, $20
    ldh [$b8], a
    ld [$2000], a
    call $4000
    ret


Jump_000_096f:
    ld a, [hl]
    cp $ed
    jr nz, jr_000_0993

    ld a, $01
    ld [$df00], a
    inc hl
    ld a, [hl+]
    ld [$df01], a
    ld a, [hl+]

Call_000_097f:
Jump_000_097f:
    push af
    ld a, [hl]
    push af
    pop af
    ld h, a
    pop af
    ld l, a
    ldh a, [$b8]
    ld [$df02], a
    ld a, [$df01]
    ldh [$b8], a
    ld [$2000], a

jr_000_0993:
    call Call_000_05f1
    ld a, [$df00]
    cp $01
    jr nz, jr_000_09a0

    call RST_30

jr_000_09a0:
    ret


Jump_000_09a1:
    ld a, [de]
    cp $ed
    jr nz, jr_000_09c7

    ld a, $02
    ld [$df00], a
    inc de

Jump_000_09ac:
    ld a, [de]
    inc de
    ld [$df01], a
    ld a, [de]
    push af
    inc de
    ld a, [de]
    push af
    pop af
    ld d, a
    pop af
    ld e, a
    ldh a, [$b8]
    ld [$df02], a
    ld a, [$df01]
    ldh [$b8], a
    ld [$2000], a

jr_000_09c7:
    ret


    ld a, [c]
    ld c, l
    ld a, a
    xor d
    ld a, $5d
    inc e

Jump_000_09cf:
    call Call_000_0a96
    call Call_000_3e15
    ld c, $20
    call Call_000_3781

Jump_000_09da:
    di
    xor a
    ldh [rIF], a
    ldh [rIE], a
    ldh [rSCX], a
    ldh [rSCY], a
    ldh [rSB], a
    ldh [rSC], a
    ldh [rWX], a
    ldh [rWY], a
    ldh [rTMA], a
    ldh [rTAC], a
    ldh [rBGP], a
    ldh [rOBP0], a
    ldh [rOBP1], a
    ld a, $80
    ldh [rLCDC], a

Jump_000_09fa:
    call Call_000_0167
    ld sp, $dfff
    ld hl, $c000
    ld bc, $2000

Call_000_0a06:
Jump_000_0a06:
jr_000_0a06:
    ld [hl], $00
    inc hl

Jump_000_0a09:
    dec bc

Call_000_0a0a:
Jump_000_0a0a:
    ld a, b
    or c
    jr nz, jr_000_0a06

Jump_000_0a0e:
    call Call_000_0a8c
    ld hl, $ff80
    ld bc, $007f
    call Call_000_372a
    call Call_000_0188
    ld a, $01
    ldh [$b8], a
    ld [$2000], a
    call $4750
    xor a
    ldh [$d7], a
    ldh [rSTAT], a
    ldh [$ae], a
    ldh [$af], a
    ldh [rIF], a
    ld a, $0d
    ldh [rIE], a
    ld a, $90
    ldh [$b0], a
    ldh [rWY], a
    ld a, $07
    ldh [rWX], a
    ld a, $ff

Jump_000_0a42:
    ldh [$aa], a
    ld h, $98

Call_000_0a46:
    call Call_000_0787
    ld h, $9c
    call Call_000_0787
    ld a, $e3

Call_000_0a50:
    ldh [rLCDC], a
    ld a, $10
    ldh [$8a], a
    call Call_000_0a96
    ei
    ld a, $40
    call Call_000_3e9d
    ld a, $1f
    ld [$c0ef], a
    ld [$c0f0], a
    ld a, $9c
    ld [$ffbd], a
    xor a
    ld [$ffbc], a
    dec a
    ld [$cfb2], a
    ld a, $32

Jump_000_0a76:
    call Call_000_3e9d
    call Call_000_0167
    call Call_000_0a8c
    call Call_000_3e0c
    call Call_000_0188
    ld a, $e3
    ldh [rLCDC], a
    jp $476e


Call_000_0a8c:
    ld hl, $8000
    ld bc, $2000
    xor a
    jp Jump_000_372a


Call_000_0a96:
Jump_000_0a96:
    ld a, $02
    ld [$c0ef], a
    ld [$c0f0], a
    xor a
    ld [$cfae], a
    ld [$c0ee], a
    ld [$cfb1], a
    dec a

Jump_000_0aa9:
    jp Jump_000_0e45


Jump_000_0aac:
    push af
    push bc
    push de
    push hl
    ldh a, [$b8]
    ld [$d0e7], a
    ldh a, [$ae]
    ldh [rSCX], a
    ldh a, [$af]
    ldh [rSCY], a
    ld a, [$d07d]
    and a
    jr nz, jr_000_0ac7

Call_000_0ac3:
    ldh a, [$b0]
    ldh [rWY], a

jr_000_0ac7:
    call Call_000_07ee
    call Call_000_087e
    call Call_000_0798
    call Call_000_08fb
    call Call_000_089f
    call Call_000_095b
    call $ff80
    ld a, $01
    ldh [$b8], a
    ld [$2000], a
    call $4672
    call Call_000_3e8c
    ldh a, [$d6]
    and a
    jr z, jr_000_0af1

    xor a
    ldh [$d6], a

jr_000_0af1:
    ldh a, [$d5]
    and a
    jr z, jr_000_0af9

    dec a
    ldh [$d5], a

jr_000_0af9:
    call Call_000_139c

Call_000_0afc:
    ld a, [$c0ef]
    ldh [$b8], a

Jump_000_0b01:
    ld [$2000], a
    cp $02

Call_000_0b06:
    jr nz, jr_000_0b0d

    call $4000
    jr jr_000_0b1c

jr_000_0b0d:
    cp $08
    jr nz, jr_000_0b19

    call $6c38
    call $455f
    jr jr_000_0b1c

jr_000_0b19:
    call $4417

jr_000_0b1c:
    ld b, $06
    ld hl, $4dee
    call Call_000_3620
    ld a, [$d0e7]
    ldh [$b8], a
    ld [$2000], a
    pop hl
    pop de
    pop bc
    pop af
    reti


Call_000_0b31:
Jump_000_0b31:
    ld a, $01
    ldh [$d6], a

jr_000_0b35:
    db $76
    ldh a, [$d6]
    and a
    jr nz, jr_000_0b35

    ret


Call_000_0b3c:
Jump_000_0b3c:
    ld a, [$d2dc]
    ld b, a
    ld hl, $0b98
    ld a, l
    sub b
    ld l, a
    jr nc, jr_000_0b49

    dec h

jr_000_0b49:
    ld a, [hl+]
    ldh [rBGP], a
    ld a, [hl+]
    ldh [rOBP0], a
    ld a, [hl+]

Call_000_0b50:
    ldh [rOBP1], a
    ret


Call_000_0b53:
    ld hl, $0b8f
    ld b, $04
    jr jr_000_0b5f

Call_000_0b5a:
Jump_000_0b5a:
    ld hl, $0b9e
    ld b, $03

jr_000_0b5f:
    ld a, [hl+]
    ldh [rBGP], a
    ld a, [hl+]
    ldh [rOBP0], a
    ld a, [hl+]
    ldh [rOBP1], a
    ld c, $08

Jump_000_0b6a:
    call Call_000_3781

Call_000_0b6d:
    dec b
    jr nz, jr_000_0b5f

    ret


Call_000_0b71:
Jump_000_0b71:
    ld hl, $0b9a
    ld b, $04
    jr jr_000_0b7d

Call_000_0b78:
Jump_000_0b78:
    ld hl, $0ba3
    ld b, $03

jr_000_0b7d:
    ld a, [hl-]
    ldh [rOBP1], a
    ld a, [hl-]
    ldh [rOBP0], a
    ld a, [hl-]

Jump_000_0b84:
    ldh [rBGP], a
    ld c, $08
    call Call_000_3781
    dec b
    jr nz, jr_000_0b7d

    ret


    rst $38
    rst $38
    rst $38
    cp $fe
    ld hl, sp-$07
    db $e4
    db $e4
    db $e4
    ret nc

    ldh [$e4], a
    ret nc

    ldh [$90], a
    add b
    sub b
    ld b, b
    ld b, b
    ld b, b
    nop
    nop
    nop

; ── SerialISR: シリアル転送完了割り込みハンドラ ──
; Game Boyのシリアルポートで1バイト転送が完了するたびに発火。
; HRAM変数:
;   $FF:$AA = ロール状態 ($FF=未確定, $01=スレーブ, $02=マスター)
;   $FF:$AC = 送信バイト (次に送るデータ)
;   $FF:$AD = 受信バイト (受け取ったデータ)
;   $FF:$A9 = 転送完了フラグ (1=完了)
; 処理フロー:
;   $AA=$FF → 初回接続: 受信値でロール確定 (→ SerialISR_HandleRole)
;   $AA=$01 → スレーブ: rSC=$80 で外部クロック受信待ちを再開
;   $AA=$02 → マスター: 次バイトの送信準備のみ
Jump_000_0ba7:
    push af
    push bc
    push de
    push hl
    ldh a, [$aa]        ; ロール状態をチェック
    inc a               ; $FF + 1 = 0 → 未確定なら Z フラグ
    jr z, jr_000_0bc4   ; → 初回: ロール確定処理へ

    ldh a, [rSB]        ; 受信バイトを取得
    ldh [$ad], a        ; → $FF:$AD に保存
    ldh a, [$ac]        ; 次の送信バイトを
    ldh [rSB], a        ;   rSB にセット
    ldh a, [$aa]
    cp $02              ; マスター?
    jr z, jr_000_0be4   ; → マスターは転送開始不要 (呼び出し側が制御)

    ld a, $80           ; スレーブ: 外部クロック受信待ち
    ldh [rSC], a
    jr jr_000_0be4

; ── SerialISR_HandleRole: 初回接続時のロール確定 ──
; 受信バイトの値でマスター/スレーブを判定:
;   $02 → 自分はマスター (相手がスレーブとして応答)
;   それ以外 → 自分はスレーブ (DIVタイマーで遅延後、外部クロック待ち)
jr_000_0bc4:
    ldh a, [rSB]        ; 受信バイト = ロール判定値

Call_000_0bc6:
    ldh [$ad], a        ; 受信バイトを保存
    ldh [$aa], a        ; ロール状態を確定
    cp $02
    jr z, jr_000_0be1   ; → マスター確定: rSB=0 のみ

    ; スレーブ確定: DIVタイマーで短い遅延を入れてから外部クロック待ち
    xor a
    ldh [rSB], a        ; rSB=0 (応答データなし)
    ld a, $03
    ldh [rDIV], a       ; DIVタイマーをリセット

jr_000_0bd5:
    ldh a, [rDIV]
    bit 7, a            ; DIV bit7 が 0 になるまで待機
    jr nz, jr_000_0bd5

    ld a, $80           ; 外部クロック受信待ち開始
    ldh [rSC], a
    jr jr_000_0be4

jr_000_0be1:
    xor a               ; マスター: rSB をクリア
    ldh [rSB], a

jr_000_0be4:
    ld a, $01
    ldh [$a9], a        ; 転送完了フラグをセット
    ld a, $fe
    ldh [$ac], a        ; 送信バイトを $FE (アイドル) に初期化
    pop hl
    pop de
    pop bc
    pop af
    reti


; ── SerialExchangeBlock: ブロックデータ交換 ──
; HL=送信元バッファ, DE=受信先バッファ, BC=バイト数
; 1バイトずつ SerialSendAndWait を呼び、双方向同時転送を行う。
; 初回 ($AB=1): $FD 受信時はリトライ (同期ずれ回復)
; 通常 ($AB=0): 受信データをそのまま格納
Call_000_0bf1:
    ld a, $01
    ldh [$ab], a        ; $AB=1: 初回同期モード

jr_000_0bf5:
    ld a, [hl]          ; 送信バッファから1バイト読み出し
    ldh [$ac], a        ; → 送信レジスタにセット
    call Call_000_0caa  ; SerialSendAndWait: 1バイト送受信
    push bc
    ld b, a             ; A=受信バイトを B に退避
    inc hl              ; 送信ポインタ++
    ld a, $30           ; 短い遅延ループ ($30=48回)

jr_000_0c00:
    dec a
    jr nz, jr_000_0c00

    ldh a, [$ab]        ; 初回同期モード?
    and a
    ld a, b
    pop bc
    jr z, jr_000_0c14   ; → 通常モード: データ格納へ

    ; 初回同期モード: $FD なら送信ポインタを戻してリトライ
    dec hl
    cp $fd
    jr nz, jr_000_0bf5  ; $FD でなければ再送

Jump_000_0c0f:
    xor a
    ldh [$ab], a        ; $AB=0: 通常モードに移行
    jr jr_000_0bf5

jr_000_0c14:
    ; 受信データを格納
    push af
    ld a, [$d0f0]       ; 通信モード判定
    cp $05              ; バトルモード?
    jr nz, jr_000_0c25

    ldh a, [$aa]
    cp $02              ; マスター?
    jr nz, jr_000_0c25

    ld de, $cd68        ; マスター+バトル時は固定バッファに格納

jr_000_0c25:
    pop af
    ld [de], a          ; 受信バイトを格納
    inc de              ; 受信ポインタ++
    dec bc              ; 残りバイト数--
    ld a, b
    or c
    jr nz, jr_000_0bf5  ; 全バイト完了まで繰り返し

    ret


; ── SerialExchangeSmall: 小規模データ交換 (2バイト) ──
; $CC42-$CC43 → 送信, $CC3D-$CC3E → 受信
; メニュー選択の同期などに使用
Call_000_0c2e:
    ld hl, $cc42        ; 送信元: $CC42
    ld de, $cc3d        ; 受信先: $CC3D
    ld c, $02           ; 2バイト
    ld a, $01
    ldh [$ab], a        ; 初回同期モード

jr_000_0c3a:
    call Call_000_0b31
    ld a, [hl]
    ldh [$ac], a
    call Call_000_0caa
    ld b, a
    inc hl
    ldh a, [$ab]
    and a

Call_000_0c48:
    ld a, $00
    ldh [$ab], a
    jr nz, jr_000_0c3a

    ld a, b
    ld [de], a

Call_000_0c50:
Jump_000_0c50:
    inc de
    dec c
    jr nz, jr_000_0c3a

    ret


Call_000_0c55:
    call Call_000_3761
    ld hl, $49ee
    ld b, $01
    call Call_000_3620
    call Call_000_0c66
    jp Jump_000_376d


; ── SerialSyncWait: ニブル同期待ち ──
; SerialSendNibble を繰り返し呼び、相手からの応答を待つ。
; $CC3E に有効な値 (!= $FF) が入ったら同期成功。
; タイムアウト ($CC47-$CC48) で切断。
Call_000_0c66:
    ld a, $ff
    ld [$cc3e], a       ; 受信値を無効値で初期化

jr_000_0c6b:
    call Call_000_0d57  ; SerialSendNibble
    call Call_000_0b31  ; VBlank待ち
    call Call_000_0d47  ; SerialCheckTimeout
    jr z, jr_000_0c87   ; タイムアウトカウンタ=0 → 応答チェックへ

    push hl
    ld hl, $cc48        ; タイムアウトカウンタ下位
    dec [hl]
    jr nz, jr_000_0c86

    dec hl              ; $CC47: 上位
    dec [hl]
    jr nz, jr_000_0c86

    pop hl
    xor a
    jp Jump_000_0d4f    ; タイムアウト → カウンタクリアして終了


jr_000_0c86:
    pop hl

jr_000_0c87:
    ld a, [$cc3e]       ; 受信ニブル
    inc a               ; $FF + 1 = 0 → まだ未受信

Jump_000_0c8b:
    jr z, jr_000_0c6b   ; → 再送ループ

    ld b, $0a           ; 同期成功: 10回追加送信して安定化

jr_000_0c8f:
    call Call_000_0b31
    call Call_000_0d57  ; SerialSendNibble
    dec b
    jr nz, jr_000_0c8f

    ld b, $0a

jr_000_0c9a:
    call Call_000_0b31
    call Call_000_0d81
    dec b
    jr nz, jr_000_0c9a

; ── SerialStoreResult: 受信ニブルを確定 ──
Call_000_0ca3:
    ld a, [$cc3e]       ; 受信ニブル (下位4bit)
    ld [$cc3d], a       ; → 確定バッファに格納
    ret


; ── SerialSendAndWait: 1バイト送受信 ──
; 事前に $FF:$AC に送信バイトをセットして呼ぶ。
; マスター ($AA=$02): rSC=$81 で内部クロック転送を開始
; スレーブ ($AA=$01): ISRが外部クロックで転送完了するのを待つ
; 戻り値: A = 受信バイト ($FF:$AD)
; $FE受信 = アイドル (相手がまだ準備できていない) → リトライ
Call_000_0caa:
Jump_000_0caa:
    xor a
    ldh [$a9], a        ; 転送完了フラグをクリア
    ldh a, [$aa]
    cp $02              ; マスター?
    jr nz, jr_000_0cb7  ; → スレーブは待つだけ

; SerialStartMaster: 内部クロックで転送開始
Call_000_0cb3:
    ld a, $81           ; rSC bit7=開始, bit0=内部クロック
    ldh [rSC], a

; 転送完了待ちループ
jr_000_0cb7:
    ldh a, [$a9]        ; ISRが完了フラグをセットしたか?
    and a
    jr nz, jr_000_0d01  ; → 完了: 結果処理へ

    ldh a, [$aa]
    cp $01              ; スレーブ?
    jr nz, jr_000_0cdc  ; → マスターでもない: 別のタイムアウトへ

    ; スレーブのタイムアウト処理
Jump_000_0cc2:
    call Call_000_0d47  ; SerialCheckTimeout
    jr z, jr_000_0cdc   ; カウンタ=0 → 通常タイムアウトへ

    call Call_000_0d41  ; SerialBusyWait (短い遅延)
    push hl
    ld hl, $cc48        ; タイムアウトカウンタ++
    inc [hl]
    jr nz, jr_000_0cd3

    dec hl              ; 上位バイトもインクリメント
    inc [hl]

jr_000_0cd3:
    pop hl
    call Call_000_0d47  ; まだタイムアウトしていない?
    jr nz, jr_000_0cb7  ; → 待ちループ継続

    jp Jump_000_0d4f    ; タイムアウト → カウンタクリア

; マスターのタイムアウト処理 (rIE=$08 = シリアルのみ有効時)
jr_000_0cdc:
    ldh a, [rIE]
    and $0f
    cp $08              ; シリアル割り込みのみ有効?
    jr nz, jr_000_0cb7  ; → 他の割り込みも有効なら待ち続ける

    ld a, [$d051]       ; フレームカウンタ下位
    dec a
    ld [$d051], a
    jr nz, jr_000_0cb7

    ld a, [$d052]       ; フレームカウンタ上位
    dec a

Jump_000_0cf1:
    ld [$d052], a
    jr nz, jr_000_0cb7

    ldh a, [$aa]
    cp $01              ; スレーブ?

Call_000_0cfa:
    jr z, jr_000_0d01   ; → スレーブは即完了扱い

    ld a, $ff           ; マスター: 短い遅延ループ

Call_000_0cfe:
jr_000_0cfe:
    dec a
    jr nz, jr_000_0cfe

; 転送完了 → 結果処理
Jump_000_0d01:
jr_000_0d01:
    xor a
    ldh [$a9], a        ; 完了フラグをクリア
    ldh a, [rIE]
    and $0f
    sub $08             ; シリアルのみモードだった?
    jr nz, jr_000_0d14

    ld [$d051], a       ; フレームカウンタをリセット
    ld a, $50
    ld [$d052], a       ; 上位=$50 (次のタイムアウト値)

jr_000_0d14:
    ldh a, [$ad]        ; 受信バイト
    cp $fe              ; アイドル値?
    ret nz              ; → 有効データ: A=受信値で return

    ; $FE (アイドル) を受信 → リトライ判定
    call Call_000_0d47  ; SerialCheckTimeout
    jr z, jr_000_0d2f   ; カウンタ=0 → リトライへ

    push hl
    ld hl, $cc48        ; タイムアウトカウンタ--
    ld a, [hl]
    dec a
    ld [hl-], a
    inc a
    jr nz, jr_000_0d29

    dec [hl]

jr_000_0d29:
    pop hl
    call Call_000_0d47
    jr z, jr_000_0d4f   ; カウンタ=0 → タイムアウト

jr_000_0d2f:
    ldh a, [rIE]
    and $0f
    cp $08
    ld a, $fe
    ret z               ; シリアルのみモード: $FE を返す

    ; 通常モード: 同じデータで再送
    ld a, [hl]
    ldh [$ac], a        ; 送信バイトを再セット
    call Call_000_0b31  ; VBlank待ち
    jp Jump_000_0caa    ; → 送受信リトライ


; ── SerialBusyWait: 短い遅延ループ ──
Call_000_0d41:
    ld a, $0f           ; $0F=15回ループ

jr_000_0d43:
    dec a
    jr nz, jr_000_0d43

Call_000_0d46:
    ret


; ── SerialCheckTimeout: タイムアウト判定 ──
; $CC47 (上位) | $CC48 (下位) が非ゼロなら Z=0 (タイムアウト未到達)
Call_000_0d47:
    push hl
    ld hl, $cc47
    ld a, [hl+]         ; $CC47
    or [hl]             ; | $CC48
    pop hl
    ret                  ; Z=1: タイムアウト, Z=0: まだ


; ── SerialSetTimeout: タイムアウトカウンタをクリア ──
Jump_000_0d4f:
jr_000_0d4f:
    dec a               ; A=0 → $FF

; ── SerialSetTimeoutValue: タイムアウト値をセット ──
Call_000_0d50:
Jump_000_0d50:
    ld [$cc47], a
    ld [$cc48], a
    ret


; ── SerialSendNibble: ニブル送信 (メニュー同期用) ──
; $CC42 の下位4bitに $60 を加算して送信。
; 上位4bit = $6 がニブルプロトコルのマーカー。
; 同時に受信ニブルのチェックも行う (→ SerialReceiveNibble)。
Call_000_0d57:
    call Call_000_0d6b  ; まず受信チェック
    ld a, [$cc42]       ; 送信ニブル値
    add $60             ; $6x フォーマット (上位=$6がマーカー)
    ldh [$ac], a        ; → 送信レジスタ
    ldh a, [$aa]
    cp $02              ; マスター?
    jr nz, jr_000_0d6b  ; → スレーブは送信開始不要

    ld a, $81           ; マスター: 内部クロックで転送開始
    ldh [rSC], a

; ── SerialReceiveNibble: ニブル受信チェック ──
; 受信バイトの上位4bit=$6 なら有効なニブル。
; 下位4bit を $CC3E に格納。
Call_000_0d6b:
jr_000_0d6b:
    ldh a, [$ad]        ; 受信バイト
    ld [$cc3d], a
    and $f0             ; 上位4bit
    cp $60              ; $6x マーカー?
    ret nz              ; → 無効: 何もしない

    xor a
    ldh [$ad], a        ; 受信バイトをクリア (処理済み)
    ld a, [$cc3d]
    and $0f             ; 下位4bit = ニブルデータ
    ld [$cc3e], a       ; → ニブル受信バッファ
    ret


; ── SerialSendZero: ゼロバイト送信 ──
Call_000_0d81:
    xor a               ; A=0

; ── SerialSendByte: 任意バイト送信 ──
; マスターの場合のみ rSC=$81 で転送開始。
; スレーブは ISR が転送を処理するので何もしない。
Call_000_0d82:
    ldh [$ac], a        ; 送信バイトをセット
    ldh a, [$aa]
    cp $02              ; マスター?
    ret nz              ; → スレーブ: return

    ld a, $81           ; 内部クロック転送開始
    ldh [rSC], a
    ret


; ── SerialInitSlave: スレーブモード初期化 ──
; rSB=$02 (テストバイト), $AD=0, rSC=$80 (外部クロック受信待ち)
Call_000_0d8e:
    ld a, $02
    ldh [rSB], a        ; テストバイト送信準備
    xor a

Jump_000_0d93:
    ldh [$ad], a        ; 受信バッファクリア

; ── SerialStartExtClock: 外部クロック受信開始 ──
Jump_000_0d95:
    ld a, $80           ; rSC: 転送開始, 外部クロック
    ldh [rSC], a
    ret


Jump_000_0d9a:
    reti


Call_000_0d9b:
Jump_000_0d9b:
    call Call_000_3790
    xor a
    ld c, a
    ld d, a
    ld [$cfb1], a
    jr jr_000_0db8

Call_000_0da6:
    ld c, $0a
    ld d, $00
    ld a, [$d6ad]
    bit 5, a
    jr z, jr_000_0db8

    xor a
    ld [$cfb1], a
    ld c, $08
    ld d, c

jr_000_0db8:
    ld a, [$d67f]
    and a
    jr z, jr_000_0dd7

    cp $02
    jr z, jr_000_0dc6

    ld a, $d2
    jr jr_000_0dc8

jr_000_0dc6:
    ld a, $d6

jr_000_0dc8:
    ld b, a
    ld a, d
    and a
    ld a, $1f
    jr nz, jr_000_0dd2

    ld [$c0ef], a

jr_000_0dd2:
    ld [$c0f0], a
    jr jr_000_0de0

jr_000_0dd7:
    ld a, [$d2da]
    ld b, a
    call Call_000_0e19
    jr c, jr_000_0de5

jr_000_0de0:
    ld a, [$cfb1]
    cp b
    ret z

jr_000_0de5:
    ld a, c
    ld [$cfae], a
    ld a, b
    ld [$cfb1], a
    ld [$c0ee], a
    jp Jump_000_0e45


Call_000_0df3:
    ld a, [$c0ef]
    ld b, a
    cp $02
    jr nz, jr_000_0e00

Jump_000_0dfb:
    ld hl, $4000

Call_000_0dfe:
    jr jr_000_0e0c

jr_000_0e00:
    cp $08
    jr nz, jr_000_0e09

    ld hl, $455f
    jr jr_000_0e0c

jr_000_0e09:
    ld hl, $4417

jr_000_0e0c:
    ld c, $06

jr_000_0e0e:
    push bc
    push hl
    call Call_000_3620
    pop hl
    pop bc
    dec c
    jr nz, jr_000_0e0e

    ret


Call_000_0e19:
    ld a, [$d2db]
    ld e, a
    ld a, [$c0ef]
    cp e
    jr nz, jr_000_0e28

    ld [$c0f0], a
    and a
    ret


jr_000_0e28:
    ld a, c
    and a
    ld a, e
    jr nz, jr_000_0e30

    ld [$c0ef], a

jr_000_0e30:
    ld [$c0f0], a
    scf
    ret


Call_000_0e35:
Jump_000_0e35:
    ld b, a
    ld [$c0ee], a
    xor a

Jump_000_0e3a:
    ld [$cfae], a
    ld a, c
    ld [$c0ef], a
    ld [$c0f0], a
    ld a, b

Call_000_0e45:
Jump_000_0e45:
    push hl
    push de

Call_000_0e47:
    push bc
    ld b, a
    ld a, [$c0ee]
    and a
    jr z, jr_000_0e5c

    xor a

Call_000_0e50:
Jump_000_0e50:
    ld [$c02a], a
    ld [$c02b], a
    ld [$c02c], a
    ld [$c02d], a

jr_000_0e5c:
    ld a, [$cfae]
    and a
    jr z, jr_000_0e77

    ld a, [$c0ee]
    and a
    jr z, jr_000_0eb9

    xor a
    ld [$c0ee], a
    ld a, [$cfb1]
    cp $ff
    jr nz, jr_000_0ea8

    xor a
    ld [$cfae], a

jr_000_0e77:
    xor a
    ld [$c0ee], a
    ldh a, [$b8]
    ldh [$b9], a
    ld a, [$c0ef]

Jump_000_0e82:
    ldh [$b8], a
    ld [$2000], a
    cp $02
    jr nz, jr_000_0e91

    ld a, b
    call $4773
    jr jr_000_0e9f

jr_000_0e91:
    cp $08
    jr nz, jr_000_0e9b

    ld a, b
    call $4d1b
    jr jr_000_0e9f

jr_000_0e9b:
    ld a, b
    call $4b8a

jr_000_0e9f:
    ldh a, [$b9]
    ldh [$b8], a
    ld [$2000], a
    jr jr_000_0eb9

jr_000_0ea8:
    ld a, b
    ld [$cfb1], a
    ld a, [$cfae]
    ld [$cfaf], a
    ld [$cfb0], a
    ld a, b
    ld [$cfae], a

jr_000_0eb9:
    pop bc
    pop de
    pop hl
    ret


Call_000_0ebd:
Jump_000_0ebd:
    ld a, [$cfb2]
    dec a
    ret nz

    ldh a, [$b8]
    push af
    ld a, $01
    ldh [$b8], a
    ld [$2000], a

Jump_000_0ecc:
    call $4a1d
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


    cp $04
    inc b
    dec bc
    rrca
    inc c
    rst $38
    cp $07
    inc b
    inc d
    dec e
    dec bc
    inc c
    ld c, $0f
    rst $38
    cp $07
    inc b
    inc d
    ld e, $0b
    inc c
    ld c, $0f
    rst $38
    cp $01
    ld b, $ff
    cp $06
    inc b
    inc de
    dec c
    ld c, $0f
    ld e, $ff
    cp $09

Jump_000_0f00:
    inc bc
    inc de
    dec [hl]

Jump_000_0f03:
    dec e

Jump_000_0f04:
    jr c, jr_000_0f11

    inc c
    dec c
    rrca

Jump_000_0f09:
    rst $38
    cp $09

Jump_000_0f0c:
    inc bc
    inc de
    dec [hl]
    jr c, @+$0d

jr_000_0f11:
    inc c
    dec c
    ld c, $0f
    rst $38
    cp $09
    add sp, -$17
    jp z, $edcf

    ret


    call $d9d1
    rst $38
    cp $05

Call_000_0f24:
    inc sp
    jr nz, jr_000_0f48

    ld [hl+], a
    cpl
    rst $38

Jump_000_0f2a:
    cp $07
    ld l, $37
    ld a, [hl-]

Call_000_0f2f:
    ld b, c
    ld b, d
    ld b, e
    ld b, h
    rst $38
    cp $04
    inc h
    dec h
    ld h, $27
    rst $38
    cp $06
    ld [bc], a
    inc bc
    inc de
    dec [hl]
    inc [hl]
    jr c, @+$01

    cp $05

Call_000_0f46:
    inc bc

Call_000_0f47:
    ld [de], a

jr_000_0f48:
    inc de

Call_000_0f49:
    inc [hl]
    dec [hl]

Call_000_0f4b:
    rst $38
    cp $07
    ld [bc], a

Jump_000_0f4f:
    inc bc

Call_000_0f50:
Jump_000_0f50:
    ld [de], a
    add hl, sp
    dec e
    inc [hl]
    dec [hl]
    rst $38
    cp $06
    inc bc
    ld [de], a
    add hl, sp
    dec e
    inc [hl]
    dec [hl]
    rst $38
    cp $07
    ld [bc], a
    inc bc
    db $10
    ld de, $3534
    add hl, sp
    rst $38
    ld d, b

Jump_000_0f6a:
    ld hl, $0f69
    ret


    nop
    rst $20
    ld d, a
    nop
    inc [hl]
    cp d
    or [hl]
    inc sp
    ld a, a
    inc l
    jp nc, $26de

    db $d3
    ret c

    or c
    ld h, $df
    ret nz

    rst $20

Call_000_0f82:
    ld d, a
    db $ed

Call_000_0f84:
    dec l
    inc sp
    ld c, c
    ret c

    or a
    ld [hl], c
    ld a, a
    inc sp
    ld a, a
    or e
    ld a, [hl+]
    or [hl]
    cp [hl]
    reti


    or [hl]
    db $d3
    ld d, [hl]
    ld d, a
    db $ed
    inc l
    pop hl
    db $76
    xor h
    inc c
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    rst $20
    ld c, a
    sbc e
    and a
    xor e

Call_000_0fa7:
    inc de
    ret c

    or b
    adc e
    xor a
    xor h
    ld b, d
    ld d, a
    db $ed
    inc l

Jump_000_0fb1:
    inc de
    ld [hl], a
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    ld a, a
    or [hl]
    or d
    call z, $e7b8
    ld c, a
    ld d, h
    adc l
    xor e
    adc a
    db $e3
    ld d, a
    ld [$5c3e], sp
    call Call_000_3e9d
    jp Jump_000_0f6a


Jump_000_0fce:
    ld b, a
    ldh a, [$b8]
    push af
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ld a, $0a
    ld [$0000], a
    xor a
    ld [$4000], a
    call Call_000_0feb
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_0feb:
    ld hl, $a188
    ld c, $10
    ld b, $03
    xor a
    call Call_000_372a
    ld a, $01
    ld [$d083], a
    ld a, $03
    ld [$d084], a
    xor a

Call_000_1001:
    ld [$d07e], a
    ld [$d07f], a
    ld [$d085], a

Jump_000_100a:
    call Call_000_115c
    ld b, a
    and $0f
    add a
    add a
    add a
    ld [$d081], a

Jump_000_1016:
    ld a, b
    swap a
    and $0f
    add a
    add a
    add a
    ld [$d080], a
    call Call_000_1141
    ld [$d085], a

Jump_000_1027:
    ld hl, $a188
    ld a, [$d085]
    bit 0, a
    jr z, jr_000_1034

    ld hl, $a310

jr_000_1034:
    call Call_000_1368
    ld a, [$d085]
    bit 1, a
    jr z, jr_000_104b

    call Call_000_1141
    and a
    jr z, jr_000_1048

    call Call_000_1141
    inc a

jr_000_1048:
    ld [$d086], a

jr_000_104b:
    call Call_000_1141
    and a
    jr z, jr_000_1066

jr_000_1051:
    call Call_000_1141

Call_000_1054:
    ld c, a
    call Call_000_1141
    sla c
    or c
    and a
    jr z, jr_000_1066

    call Call_000_111a
    call Call_000_10a9
    jr jr_000_1051

jr_000_1066:
    ld c, $00

jr_000_1068:
    call Call_000_1141
    and a
    jr z, jr_000_1071

    inc c
    jr jr_000_1068

jr_000_1071:
    ld a, c
    add a
    ld hl, $1170
    add l
    ld l, a
    jr nc, jr_000_107b

    inc h

jr_000_107b:
    ld a, [hl+]
    ld e, a
    ld d, [hl]
    push de
    inc c
    ld e, $00
    ld d, e

jr_000_1083:
    call Call_000_1141
    or e
    ld e, a
    dec c
    jr z, jr_000_1091

    sla e
    rl d
    jr jr_000_1083

jr_000_1091:
    pop hl
    add hl, de
    ld e, l
    ld d, h

jr_000_1095:
    ld b, e
    xor a
    call Call_000_111a
    ld e, b
    call Call_000_10a9
    dec de
    ld a, d
    and a
    jr nz, jr_000_10a5

    ld a, e
    and a

jr_000_10a5:
    jr nz, jr_000_1095

    jr jr_000_1051

Call_000_10a9:
    ld a, [$d081]
    ld b, a
    ld a, [$d07f]
    inc a
    cp b
    jr z, jr_000_10c7

    ld [$d07f], a
    ld a, [$d08a]
    inc a
    ld [$d08a], a
    ret nz

    ld a, [$d08b]

Call_000_10c2:
    inc a
    ld [$d08b], a
    ret


Call_000_10c7:
jr_000_10c7:
    xor a
    ld [$d07f], a
    ld a, [$d084]
    and a
    jr z, jr_000_10e1

    dec a
    ld [$d084], a
    ld hl, $d08c

Jump_000_10d8:
    ld a, [hl+]

Call_000_10d9:
    ld [$d08a], a
    ld a, [hl]
    ld [$d08b], a
    ret


jr_000_10e1:
    ld a, $03
    ld [$d084], a
    ld a, [$d07e]
    add $08
    ld [$d07e], a
    ld b, a
    ld a, [$d080]
    cp b
    jr z, jr_000_1101

    ld a, [$d08a]
    ld l, a
    ld a, [$d08b]
    ld h, a

Jump_000_10fd:
    inc hl

Jump_000_10fe:
    jp Jump_000_1368


jr_000_1101:
    pop hl

Call_000_1102:
    xor a
    ld [$d07e], a
    ld a, [$d085]

Jump_000_1109:
    bit 1, a
    jr nz, jr_000_1117

    xor $01
    set 1, a
    ld [$d085], a
    jp Jump_000_1027


jr_000_1117:
    jp Jump_000_1190


Call_000_111a:
    ld e, a
    ld a, [$d084]
    and a
    jr z, jr_000_1135

    cp $02
    jr c, jr_000_112d

    jr z, jr_000_1133

    rrc e
    rrc e
    jr jr_000_1135

jr_000_112d:
    sla e
    sla e

Jump_000_1131:
    jr jr_000_1135

jr_000_1133:
    swap e

jr_000_1135:
    ld a, [$d08a]
    ld l, a
    ld a, [$d08b]
    ld h, a
    ld a, [hl]
    or e
    ld [hl], a
    ret


Call_000_1141:
    ld a, [$d083]
    dec a
    jr nz, jr_000_114f

    call Call_000_115c
    ld [$d082], a
    ld a, $08

jr_000_114f:
    ld [$d083], a

Jump_000_1152:
    ld a, [$d082]
    rlca
    ld [$d082], a
    and $01
    ret


Call_000_115c:
    ld a, [$d088]
    ld l, a
    ld a, [$d089]
    ld h, a
    ld a, [hl+]
    ld b, a
    ld a, l
    ld [$d088], a
    ld a, h
    ld [$d089], a
    ld a, b
    ret


    ld bc, $0300
    nop
    rlca
    nop
    rrca
    nop
    rra
    nop
    ccf
    nop
    ld a, a
    nop
    rst $38
    nop
    rst $38
    ld bc, $03ff

Call_000_1184:
    rst $38
    rlca
    rst $38
    rrca
    rst $38
    rra
    rst $38
    ccf
    rst $38
    ld a, a
    rst $38
    rst $38

Jump_000_1190:
    ld a, [$d086]
    cp $02
    jp z, Jump_000_1348

    and a
    jp nz, Jump_000_1298

    ld hl, $a188
    call Call_000_11a5

Call_000_11a2:
    ld hl, $a310

Call_000_11a5:
    xor a
    ld [$d07e], a
    ld [$d07f], a
    call Call_000_1368
    ld a, [$d087]
    and a
    jr z, jr_000_11bd

    ld hl, $1288
    ld de, $1290
    jr jr_000_11c3

jr_000_11bd:
    ld hl, $1278
    ld de, $1280

jr_000_11c3:
    ld a, l
    ld [$d08e], a

Call_000_11c7:
    ld a, h
    ld [$d08f], a
    ld a, e
    ld [$d090], a
    ld a, d
    ld [$d091], a
    ld e, $00

jr_000_11d5:
    ld a, [$d08a]
    ld l, a
    ld a, [$d08b]

Jump_000_11dc:
    ld h, a
    ld a, [hl]
    ld b, a
    swap a
    and $0f
    call Call_000_123e
    swap a
    ld d, a
    ld a, b
    and $0f
    call Call_000_123e
    or d
    ld b, a
    ld a, [$d08a]
    ld l, a
    ld a, [$d08b]
    ld h, a
    ld a, b
    ld [hl], a
    ld a, [$d081]
    add l

Jump_000_11ff:
    jr nc, jr_000_1202

Jump_000_1201:
    inc h

jr_000_1202:
    ld [$d08a], a

Jump_000_1205:
    ld a, h
    ld [$d08b], a
    ld a, [$d07e]
    add $08

Jump_000_120e:
    ld [$d07e], a
    ld b, a
    ld a, [$d080]
    cp b
    jr nz, jr_000_11d5

    xor a
    ld e, a
    ld [$d07e], a
    ld a, [$d07f]
    inc a
    ld [$d07f], a
    ld b, a
    ld a, [$d081]
    cp b
    jr z, jr_000_1239

    ld a, [$d08c]
    ld l, a
    ld a, [$d08d]
    ld h, a
    inc hl
    call Call_000_1368
    jr jr_000_11d5

jr_000_1239:
    xor a
    ld [$d07f], a

Jump_000_123d:
    ret


Call_000_123e:
    srl a
    ld c, $00

Jump_000_1242:
    jr nc, jr_000_1246

    ld c, $01

jr_000_1246:
    ld l, a
    ld a, [$d087]
    and a
    jr z, jr_000_1251

    bit 3, e
    jr jr_000_1253

jr_000_1251:
    bit 0, e

jr_000_1253:
    ld e, l
    jr nz, jr_000_125f

    ld a, [$d08e]
    ld l, a

Call_000_125a:
    ld a, [$d08f]
    jr jr_000_1266

jr_000_125f:
    ld a, [$d090]
    ld l, a
    ld a, [$d091]

jr_000_1266:
    ld h, a
    ld a, e
    add l
    ld l, a
    jr nc, jr_000_126d

    inc h

jr_000_126d:
    ld a, [hl]
    bit 0, c
    jr nz, jr_000_1274

    swap a

Jump_000_1274:
jr_000_1274:
    and $0f
    ld e, a
    ret


    ld bc, $7632
    ld b, l
    cp $cd
    adc c
    cp d
    cp $cd
    adc c
    cp d
    ld bc, $7632
    ld b, l
    ld [$e6c4], sp
    ld a, [hl+]
    rst $30
    dec sp
    add hl, de
    push de
    rst $30

Jump_000_1291:
    dec sp
    add hl, de
    push de
    ld [$e6c4], sp
    ld a, [hl+]

Jump_000_1298:
    xor a
    ld [$d07e], a
    ld [$d07f], a
    call Call_000_1312
    ld a, [$d08a]
    ld l, a

Call_000_12a6:
    ld a, [$d08b]
    ld h, a
    call Call_000_11a5
    call Call_000_1312
    ld a, [$d08a]

Call_000_12b3:
    ld l, a
    ld a, [$d08b]
    ld h, a
    ld a, [$d08c]
    ld e, a
    ld a, [$d08d]
    ld d, a

jr_000_12c0:
    ld a, [$d087]
    and a
    jr z, jr_000_12dc

    push de

Call_000_12c7:
    ld a, [de]
    ld b, a
    swap a
    and $0f
    call Call_000_1308
    swap a
    ld c, a
    ld a, b
    and $0f
    call Call_000_1308
    or c
    pop de
    ld [de], a

jr_000_12dc:
    ld a, [hl+]
    ld b, a
    ld a, [de]
    xor b
    ld [de], a
    inc de
    ld a, [$d07f]
    inc a
    ld [$d07f], a
    ld b, a
    ld a, [$d081]
    cp b
    jr nz, jr_000_12c0

    xor a
    ld [$d07f], a
    ld a, [$d07e]
    add $08
    ld [$d07e], a
    ld b, a
    ld a, [$d080]
    cp b

Call_000_1301:
    jr nz, jr_000_12c0

Call_000_1303:
    xor a

Call_000_1304:
    ld [$d07e], a
    ret


Call_000_1308:
    ld de, $1338
    add e
    ld e, a
    jr nc, jr_000_1310

    inc d

jr_000_1310:
    ld a, [de]
    ret


Call_000_1312:
    ld a, [$d085]
    bit 0, a
    jr nz, jr_000_1321

    ld de, $a188
    ld hl, $a310
    jr jr_000_1327

jr_000_1321:
    ld de, $a310
    ld hl, $a188

jr_000_1327:
    ld a, l

Jump_000_1328:
    ld [$d08a], a
    ld a, h
    ld [$d08b], a
    ld a, e
    ld [$d08c], a
    ld a, d
    ld [$d08d], a
    ret


    nop
    ld [$0c04], sp

Jump_000_133c:
    ld [bc], a
    ld a, [bc]
    ld b, $0e
    ld bc, $0509

Call_000_1343:
    dec c

Jump_000_1344:
    inc bc
    dec bc
    rlca
    rrca

Jump_000_1348:
    call Call_000_1312
    ld a, [$d087]
    push af

Jump_000_134f:
    xor a

Jump_000_1350:
    ld [$d087], a
    ld a, [$d08c]
    ld l, a
    ld a, [$d08d]
    ld h, a
    call Call_000_11a5
    call Call_000_1312
    pop af
    ld [$d087], a
    jp Jump_000_1298


Call_000_1368:
Jump_000_1368:
    ld a, l
    ld [$d08a], a
    ld [$d08c], a
    ld a, h
    ld [$d08b], a
    ld [$d08d], a
    ret


Call_000_1377:
    ld hl, $c100
    call Call_000_1395
    ld hl, $c200
    call Call_000_1395
    ld a, $01
    ld [$c100], a
    ld [$c20e], a
    ld hl, $c104
    ld [hl], $3c
    inc hl
    inc hl
    ld [hl], $40
    ret


Call_000_1395:
    ld bc, $0010
    xor a
    jp Jump_000_372a


Call_000_139c:
    ld a, [$cfae]
    and a
    jr nz, jr_000_13ad

    ld a, [$d6ab]

Call_000_13a5:
    bit 1, a
    ret nz

    ld a, $77
    ldh [rNR50], a

Call_000_13ac:
Jump_000_13ac:
    ret


jr_000_13ad:
    ld a, [$cfb0]
    and a
    jr z, jr_000_13b8

    dec a
    ld [$cfb0], a
    ret


jr_000_13b8:
    ld a, [$cfaf]
    ld [$cfb0], a
    ldh a, [rNR50]
    and a

Call_000_13c1:
    jr z, jr_000_13d4

    ld b, a
    and $0f
    dec a

Call_000_13c7:
Jump_000_13c7:
    ld c, a
    ld a, b

Jump_000_13c9:
    and $f0
    swap a
    dec a
    swap a
    or c
    ldh [rNR50], a
    ret


Jump_000_13d4:
jr_000_13d4:
    ld a, [$cfae]
    ld b, a
    xor a
    ld [$cfae], a
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld a, [$c0f0]
    ld [$c0ef], a
    ld a, b
    ld [$c0ee], a
    jp Jump_000_0e45


Call_000_13f1:
Jump_000_13f1:
    ldh a, [$b8]
    push af
    ld b, $01
    ld hl, $724c
    call Call_000_3620
    ld hl, $cf0c

Call_000_13ff:
    bit 0, [hl]
    res 0, [hl]
    jr nz, jr_000_140b

    ld a, [$d2dd]
    call Call_000_2ccd

jr_000_140b:
    ld a, $1e
    ld [$ffd5], a
    ld hl, $d2eb
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld d, $00
    ldh a, [$8c]
    ld [$cf0e], a
    and a
    jp z, Jump_000_15de

    cp $d3
    jp z, Jump_000_156f

Jump_000_1426:
    cp $d0
    jp z, Jump_000_157a

    cp $d1
    jp z, Jump_000_1590

    cp $d2
    jp z, Jump_000_15c6

    ld a, [$d460]
    ld e, a
    ldh a, [$8c]
    cp e
    jr z, jr_000_1440

    jr nc, jr_000_145c

jr_000_1440:
    push hl

Jump_000_1441:
    push de
    push bc
    ld b, $04
    ld hl, $5ad7
    call Call_000_3620
    pop bc
    pop de
    ld hl, $d463

Call_000_1450:
    ldh a, [$8c]
    dec a
    add a

Call_000_1454:
    add l
    ld l, a
    jr nc, jr_000_1459

    inc h

jr_000_1459:
    inc hl
    ld a, [hl]
    pop hl

jr_000_145c:
    dec a
    ld e, a
    sla e
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [hl]

Call_000_1465:
    cp $fe
    jp z, Jump_000_1500

    cp $ff
    jp z, Jump_000_1551

    cp $fc
    jp z, Jump_000_34aa

    cp $fd
    jp z, Jump_000_34b4

    cp $f9
    jp z, Jump_000_34c9

    cp $f5
    jr nz, jr_000_148c

    ld b, $1d
    ld hl, $4e36
    call Call_000_3620
    jr jr_000_14a8

Jump_000_148c:
jr_000_148c:
    cp $f7
    jp z, Jump_000_34be

Call_000_1491:
    cp $f6
    jr nz, jr_000_149f

    ld hl, $736c
    ld b, $01
    call Call_000_3620
    jr jr_000_14a8

jr_000_149f:
    call Call_000_3c89
    ld a, [$cc3c]
    and a
    jr nz, jr_000_14b1

Jump_000_14a8:
jr_000_14a8:
    ld a, [$cc47]
    and a
    jr nz, jr_000_14b1

    call Call_000_38ae

Jump_000_14b1:
jr_000_14b1:
    call Call_000_0153
    ldh a, [$b4]
    bit 0, a
    jr nz, jr_000_14b1

Jump_000_14ba:
    ld a, [$d2dd]
    call Call_000_2ccd
    ld a, $90
    ldh [$b0], a
    call Call_000_0b31
    call Call_000_0b3c
    xor a
    ldh [$ba], a
    ld hl, $c219
    ld c, $0f
    ld de, $0010

jr_000_14d5:
    ld a, [hl]
    dec h
    ld [hl], a
    inc h
    add hl, de
    dec c
    jr nz, jr_000_14d5

    ld a, $05
    ldh [$b8], a
    ld [$2000], a
    call $7840
    ld hl, $cfab
    res 0, [hl]
    ld a, [$d6b1]
    bit 3, a
    call z, Call_000_23ae
    call Call_000_26bb
    pop af
    ldh [$b8], a
    ld [$2000], a
    jp Jump_000_0ebd


Jump_000_1500:
    push hl

Call_000_1501:
Jump_000_1501:
    ld hl, $1527

Call_000_1504:
Jump_000_1504:
    call Call_000_3c79

Call_000_1507:
Jump_000_1507:
    pop hl

Call_000_1508:
Jump_000_1508:
    inc hl

Call_000_1509:
Jump_000_1509:
    call Call_000_1539

Call_000_150c:
    ld a, $02
    ld [$cf7b], a
    ldh a, [$b8]
    push af
    ld a, $01
    ldh [$b8], a
    ld [$2000], a
    call $6bbc
    pop af
    ldh [$b8], a
    ld [$2000], a
    jp Jump_000_14a8


    db $ed
    jr z, @+$6c

    ld d, l
    cp a
    rst $20
    ld c, [hl]
    or l
    cp e
    ld h, $bc
    db $d3
    ret


    inc sp
    cp l
    or [hl]
    and $57

Call_000_1539:
    ld a, $01
    ld [$cfb2], a
    ld a, h
    ld [$d0ed], a
    ld a, l
    ld [$d0ee], a
    ld de, $cf62

jr_000_1549:
    ld a, [hl+]
    ld [de], a

jr_000_154b:
    inc de
    cp $ff
    jr nz, jr_000_1549

    ret


Jump_000_1551:
    xor a

Call_000_1552:
    ldh [$8b], a

Call_000_1554:
    ldh [$8c], a
    ldh [$8d], a
    inc hl
    ldh a, [$b8]
    push af
    ld a, $01
    ldh [$b8], a
    ld [$2000], a
    call $7122
    pop af
    ldh [$b8], a
    ld [$2000], a
    jp Jump_000_14a8


Jump_000_156f:
    ld hl, $7a99
    ld b, $07
    call Call_000_3620
    jp Jump_000_14a8


Jump_000_157a:
    ld hl, $1583
    call Call_000_3c79
    jp Jump_000_14a8


    db $ed
    dec l
    sbc [hl]
    ld b, [hl]
    jp z, $c17f

    or [hl]
    rst $10
    jp nz, $c0b7

    ld d, a

Jump_000_1590:
    ld hl, $1599
    call Call_000_3c79
    jp Jump_000_14b1


    db $ed
    jr z, jr_000_154b

Jump_000_159c:
    ld d, l
    jp $c4d3


Call_000_15a0:
    add $ca
    ld c, a
    ret nz

Call_000_15a4:
    ret nz

    or [hl]
    or h

Call_000_15a7:
    reti


    ld d, h
    ld h, $7f
    db $d3
    or e
    or d
    push bc
    or d
    rst $20
    ld d, c

Jump_000_15b2:
    ld d, d
    jp z, $d24f

    ret


Call_000_15b7:
    rst $08
    or h
    ld h, $7f
    rst $08
    rst $18
    cp b
    rst $10
    add $7f
    push bc
    rst $18
    ret nz

    rst $20
    ld e, b

Jump_000_15c6:
    ld hl, $15cf
    call Call_000_3c79
    jp Jump_000_14a8


    db $ed
    jr z, @+$01

Jump_000_15d2:
    ld d, l

Jump_000_15d3:
    db $e3
    ret


    ld a, a

Call_000_15d6:
    cp d
    or e
    or [hl]
    ld h, $b7
    jp c, $57c0

Jump_000_15de:
    ld a, $04
    ldh [$b8], a
    ld [$2000], a
    ld a, [$d67f]
    ld [$d0df], a
    ld a, $8f
    call Call_000_0e45

Jump_000_15f0:
    ld b, $01
    ld hl, $72c1
    call Call_000_3620
    ld b, $03
    ld hl, $4b75
    call Call_000_3620
    call Call_000_0ebd

jr_000_1603:
    call Call_000_3b08
    ld b, a
    bit 6, a

Jump_000_1609:
    jr z, jr_000_1629

    ld a, [$cc26]
    and a
    jr nz, jr_000_1603

    ld a, [$cc2a]
    and a
    jr nz, jr_000_1603

    ld a, [$d6ca]
    bit 5, a
    ld a, $06
    jr nz, jr_000_1621

    dec a

jr_000_1621:
    ld [$cc26], a
    call Call_000_3c29
    jr jr_000_1603

jr_000_1629:
    bit 7, a
    jr z, jr_000_1646

    ld a, [$d6ca]
    bit 5, a
    ld a, [$cc26]
    ld c, $07
    jr nz, jr_000_163a

    dec c

jr_000_163a:
    cp c
    jr nz, jr_000_1603

    xor a
    ld [$cc26], a
    call Call_000_3c29
    jr jr_000_1603

jr_000_1646:
    call Call_000_3c1c
    ld a, [$cc26]
    ld [$cc2d], a
    ld a, b
    and $0a
    jp nz, Jump_000_1681

    call Call_000_373e
    ld a, [$d6ca]
    bit 5, a
    ld a, [$cc26]
    jr nz, jr_000_1663

    inc a

jr_000_1663:
    cp $00
    jp z, $5af8

    cp $01
    jp z, $5b0c

    cp $02
    jp z, $5de6

    cp $03
    jp z, $5f60

Jump_000_1677:
    cp $04
    jp z, $60e6

    cp $05
    jp z, $60f9

Jump_000_1681:
jr_000_1681:
    call Call_000_0153
    ldh a, [$b3]
    bit 0, a
    jr nz, jr_000_1681

    call Call_000_36ea
    jp Jump_000_14ba


Call_000_1690:
    ld c, $00

jr_000_1692:
    ld a, [hl+]
    ld e, a
    ld d, $08

jr_000_1696:
    srl e
    ld a, $00
    adc c
    ld c, a
    dec d
    jr nz, jr_000_1696

    dec b
    jr nz, jr_000_1692

    ld a, c

Jump_000_16a3:
    ld [$d0e3], a
    ret


Call_000_16a7:
    ld b, $01
    ld hl, $6abd
    jp Jump_000_3620


Call_000_16af:
    ld de, $d2cd
    ld hl, $ffa1
    ld c, $03
    ld a, $0b
    call Call_000_3e9d
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld a, $b2
    call Call_000_3788
    jp Jump_000_3790


Call_000_16cc:
Jump_000_16cc:
    ldh a, [$b8]
    push af
    ld a, $03
    ldh [$b8], a
    ld [$2000], a
    call $4652
    pop af
    ldh [$b8], a
    ld [$2000], a

Call_000_16df:
    ret


Call_000_16e0:
    push bc
    ldh a, [$b8]
    push af
    ld a, $03
    ldh [$b8], a
    ld [$2000], a
    call $45e2
    pop bc
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    pop bc
    ret


Call_000_16f7:
    xor a
    ldh [$ba], a

Call_000_16fa:
    ld a, $01
    ld [$ffb7], a
    ld a, [$d037]
    and a
    jr nz, jr_000_1709

    ld a, $01
    jr jr_000_170b

jr_000_1709:
    ld a, $0f

jr_000_170b:
    call Call_000_3606
    ld hl, $d6af
    set 6, [hl]
    xor a
    ld [$cc35], a
    ld [$d0ef], a
    ld a, [$cf72]
    ld l, a
    ld a, [$cf73]
    ld h, a
    ld a, [hl]
    ld [$d0ef], a
    ld a, $0d
    ld [$d0ea], a
    call Call_000_3130
    call Call_000_0ebd
    ld hl, $c3cc
    ld de, $090e
    ld a, [$cf7b]
    and a
    jr nz, jr_000_1740

    call Call_000_0ebd

jr_000_1740:
    ld a, $01
    ld [$cc37], a
    ld a, [$d0ef]
    cp $02
    jr c, jr_000_174e

    ld a, $02

jr_000_174e:
    ld [$cc28], a
    ld a, $04
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    ld a, $07
    ld [$cc29], a
    ld c, $0a
    call Call_000_3781

Jump_000_1765:
    xor a
    ldh [$ba], a
    call Call_000_1968
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    ld a, [$d037]
    and a
    jr z, jr_000_1793

    ld a, $ed
    ld [$c3f5], a
    ld c, $50
    call Call_000_3781
    xor a
    ld [$cc26], a
    ld hl, $c3f5
    ld a, l
    ld [$cc30], a
    ld a, h
    ld [$cc31], a
    jr jr_000_17a3

jr_000_1793:
    call Call_000_0b3c
    call Call_000_3b08
    push af
    call Call_000_3bc6
    pop af
    bit 0, a

Call_000_17a0:
    jp z, Jump_000_1840

jr_000_17a3:
    ld a, [$cc26]
    call Call_000_3c1c
    ld a, $01
    ld [$d0f3], a
    ld [$d0f2], a
    xor a
    ld [$cc37], a
    ld a, [$cc26]
    ld c, a
    ld a, [$cc36]
    add c
    ld c, a
    ld a, [$d0ef]
    and a
    jp z, Jump_000_194c

    dec a
    cp c

Call_000_17c7:
    jp c, Jump_000_194c

    ld a, c
    ld [$cf79], a
    ld a, [$cf7b]
    cp $03
    jr nz, jr_000_17d7

    sla c

jr_000_17d7:
    ld a, [$cf72]
    ld l, a
    ld a, [$cf73]
    ld h, a
    inc hl
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$cf78], a
    ld a, [$cf7b]
    and a
    jr z, jr_000_180e

    push hl
    call Call_000_3827
    pop hl
    ld a, [$cf7b]
    cp $03
    jr nz, jr_000_17fe

    inc hl
    ld a, [hl]
    ld [$cf7e], a

jr_000_17fe:
    ld a, [$cf78]
    ld [$d092], a
    ld a, $01
    ld [$d094], a
    call Call_000_37b3

Call_000_180c:
    jr jr_000_1823

jr_000_180e:
    ld hl, $d123
    ld a, [$cf72]
    cp l
    ld hl, $d257
    jr z, jr_000_181d

    ld hl, $de64

jr_000_181d:
    ld a, [$cf79]
    call Call_000_2fb1

jr_000_1823:
    ld de, $cd68

Jump_000_1826:
    call Call_000_386e
    ld a, $01
    ld [$d0f3], a
    ld a, [$cc26]
    ld [$d0f2], a
    xor a
    ld [$ffb7], a
    ld hl, $d6af
    res 6, [hl]

Jump_000_183d:
    jp Jump_000_3617


Jump_000_1840:
    bit 1, a
    jp nz, Jump_000_194c

    bit 2, a

Call_000_1847:
    jp nz, $6ae0

    ld b, a
    bit 7, b
    ld hl, $cc36
    jr z, jr_000_1861

    ld a, [hl]
    add $03
    ld b, a

Call_000_1856:
    ld a, [$d0ef]
    cp b
    jp c, Jump_000_1765

    inc [hl]
    jp Jump_000_1765


jr_000_1861:
    ld a, [hl]
    and a
    jp z, Jump_000_1765

    dec [hl]
    jp Jump_000_1765


Call_000_186a:
    ld hl, $c463
    ld b, $01
    ld c, $03
    ld a, [$cf7b]
    cp $02
    jr nz, jr_000_187f

    ld hl, $c45b
    ld b, $01
    ld c, $0b

jr_000_187f:
    call Call_000_03d2

Jump_000_1882:
    ld hl, $c478

Jump_000_1885:
    ld a, [$cf7b]
    cp $02

Call_000_188a:
    jr nz, jr_000_1894

Jump_000_188c:
    ld a, $f0
    ld [$c47a], a
    ld hl, $c470

jr_000_1894:
    ld de, $1941
    call Call_000_0405
    xor a
    ld [$cf7d], a
    jp Jump_000_18ba


Jump_000_18a1:
jr_000_18a1:
    call Call_000_3879
    ldh a, [$b3]
    bit 0, a

Jump_000_18a8:
    jp nz, Jump_000_193c

    bit 1, a
    jp nz, Jump_000_193e

    bit 6, a
    jr nz, jr_000_18ba

    bit 7, a
    jr nz, jr_000_18cc

    jr jr_000_18a1

Jump_000_18ba:
jr_000_18ba:
    ld a, [$cf7e]
    inc a
    ld b, a
    ld hl, $cf7d
    inc [hl]
    ld a, [hl]
    cp b
    jr nz, jr_000_18d6

    ld a, $01
    ld [hl], a
    jr jr_000_18d6

jr_000_18cc:
    ld hl, $cf7d
    dec [hl]
    jr nz, jr_000_18d6

    ld a, [$cf7e]
    ld [hl], a

jr_000_18d6:
    ld hl, $c479
    ld a, [$cf7b]
    cp $02
    jr nz, jr_000_1930

    ld c, $03
    ld a, [$cf7d]
    ld b, a
    ld hl, $ff9f
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a

jr_000_18ed:
    ld de, $ffa1
    ld hl, $ff8d
    push bc
    ld a, $0b
    call Call_000_3e9d
    pop bc
    dec b
    jr nz, jr_000_18ed

    ldh a, [$8e]
    and a
    jr z, jr_000_191c

    xor a
    ldh [$a2], a
    ldh [$a3], a
    ld a, $02

Call_000_1909:
    ldh [$a4], a
    ld a, $0d
    call Call_000_3e9d
    ldh a, [$a2]
    ldh [$9f], a
    ldh a, [$a3]
    ldh [$a0], a
    ldh a, [$a4]
    ldh [$a1], a

jr_000_191c:
    ld hl, $c474
    ld de, $1945
    call Call_000_0405
    ld de, $ff9f
    ld c, $83

Call_000_192a:
    call Call_000_2fc4
    ld hl, $c471

jr_000_1930:
    ld de, $cf7d
    ld bc, $8102
    call Call_000_3c8f
    jp Jump_000_18a1


Jump_000_193c:
    xor a
    ret


Jump_000_193e:
    ld a, $ff
    ret


    pop af
    or $f7

Call_000_1944:
    ld d, b
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b

Jump_000_194c:
    ld a, [$cc26]

Call_000_194f:
    ld [$d0f2], a
    ld a, $02

Call_000_1954:
    ld [$d0f3], a
    ld [$cc37], a
    xor a
    ld [$ffb7], a
    ld hl, $d6af
    res 6, [hl]
    call Call_000_3617

Call_000_1966:
    scf
    ret


Call_000_1968:
    ld hl, $c3dd
    ld b, $09
    ld c, $12
    call Call_000_0374

Call_000_1972:
    ld a, [$cf72]
    ld e, a
    ld a, [$cf73]
    ld d, a

Jump_000_197a:
    inc de
    ld a, [$cc36]
    ld c, a
    ld a, [$cf7b]
    cp $03
    ld a, c
    jr nz, jr_000_198b

    sla a
    sla c

jr_000_198b:
    add e
    ld e, a
    jr nc, jr_000_1990

    inc d

jr_000_1990:
    ld hl, $c3f2
    ld b, $04

Jump_000_1995:
    ld a, b

Call_000_1996:
    ld [$cf79], a
    ld a, [de]
    ld [$d0e3], a
    cp $ff
    jp z, Jump_000_1aa1

    push bc

Jump_000_19a3:
    push de
    push hl
    push hl
    push de
    ld a, [$cf7b]
    and a
    jr z, jr_000_19b6

    cp $01
    jr z, jr_000_19d8

    call Call_000_1add
    jr jr_000_19db

jr_000_19b6:
    push hl
    ld hl, $d123
    ld a, [$cf72]
    cp l
    ld hl, $d257
    jr z, jr_000_19c6

    ld hl, $de64

jr_000_19c6:
    ld a, [$cf79]
    ld b, a
    ld a, $04
    sub b
    ld b, a
    ld a, [$cc36]
    add b
    call Call_000_2fb1
    pop hl
    jr jr_000_19db

Call_000_19d8:
Jump_000_19d8:
jr_000_19d8:
    call Call_000_1b6d

jr_000_19db:
    call Call_000_0405
    pop de
    pop hl
    ld a, [$cf7a]
    and a
    jr z, jr_000_19fd

    push hl
    ld a, [de]

Jump_000_19e8:
    ld de, $421c
    ld [$cf78], a
    call Call_000_3827
    pop hl
    ld bc, $0018
    add hl, bc
    ld c, $83
    call Call_000_2fc4
    ld [hl], $f0

jr_000_19fd:
    ld a, [$cf7b]
    and a
    jr nz, jr_000_1a41

    ld a, [$d0e3]
    push af

Jump_000_1a07:
    push hl

Jump_000_1a08:
    ld hl, $d123
    ld a, [$cf72]
    cp l

Jump_000_1a0f:
    ld a, $00
    jr z, jr_000_1a15

    ld a, $02

jr_000_1a15:
    ld [$cc49], a
    ld hl, $cf79
    ld a, [hl]
    ld b, a
    ld a, $04
    sub b
    ld b, a
    ld a, [$cc36]
    add b
    ld [hl], a

Jump_000_1a26:
    call Call_000_2d68
    ld a, [$cc49]

Call_000_1a2c:
    and a
    jr z, jr_000_1a35

    ld a, [$cf82]
    ld [$cfa0], a

jr_000_1a35:
    pop hl
    ld bc, $0006
    add hl, bc
    call Call_000_2f02
    pop af
    ld [$d0e3], a

jr_000_1a41:
    pop hl
    pop de
    inc de
    ld a, [$cf7b]
    cp $03
    jr nz, jr_000_1a8f

    ld a, [$d0e3]
    ld [$cf78], a
    call Call_000_3121

Call_000_1a54:
    ld a, [$d0e9]
    and a
    jr nz, jr_000_1a7b

    push hl
    ld bc, $000f
    add hl, bc
    ld a, $f1
    ld [hl], a
    ld a, [$d0e3]
    push af
    ld a, [de]

Call_000_1a67:
    ld [$cf7e], a
    push de
    ld de, $d0e3
    ld [de], a
    ld bc, $0102
    call Call_000_3c8f
    pop de
    pop af
    ld [$d0e3], a
    pop hl

jr_000_1a7b:
    inc de
    pop bc
    inc c
    push bc

Call_000_1a7f:
    inc c
    ld a, [$cc35]
    and a
    jr z, jr_000_1a8f

    sla a
    cp c
    jr nz, jr_000_1a8f

    dec hl
    ld a, $ec
    ld [hl+], a

jr_000_1a8f:
    ld bc, $0028
    add hl, bc
    pop bc
    inc c
    dec b
    jp nz, Jump_000_1995

    ld bc, $fff8
    add hl, bc
    ld a, $ee
    ld [hl], a
    ret


Jump_000_1aa1:
    ld de, $1aa7
    jp Jump_000_0405


    and l
    xor [hl]
    and h

Call_000_1aaa:
    ld d, b

Call_000_1aab:
Jump_000_1aab:
    push hl
    ldh a, [$b8]
    push af

Call_000_1aaf:
    ld a, $0e
    ldh [$b8], a

Call_000_1ab3:
    ld [$2000], a
    ld a, [$d0e3]
    dec a
    ld hl, $5068
    ld e, a
    ld d, $00
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld de, $cd68
    push de
    ld bc, $0005
    call Call_000_01bb
    ld hl, $cd6d
    ld [hl], $50
    pop de
    pop af
    ldh [$b8], a
    ld [$2000], a
    pop hl
    ret


Call_000_1add:
    push hl
    push bc
    ld a, [$d0e3]
    cp $c4
    jr nc, jr_000_1af8

    ld [$d092], a
    ld a, $04
    ld [$d093], a

Jump_000_1aee:
    ld a, $01
    ld [$d094], a
    call Call_000_37b3
    jr jr_000_1afb

jr_000_1af8:
    call Call_000_1b01

jr_000_1afb:
    ld de, $cd68

Call_000_1afe:
    pop bc

Call_000_1aff:
    pop hl

Jump_000_1b00:
    ret


Call_000_1b01:
Jump_000_1b01:
    push hl
    push de
    push bc
    ld a, [$d0e3]
    push af
    cp $c9
    jr nc, jr_000_1b19

    add $05
    ld [$d0e3], a
    ld hl, $00f0
    ld bc, $000d
    jr jr_000_1b1f

jr_000_1b19:
    ld hl, $04b0
    ld bc, $000d

jr_000_1b1f:
    ld de, $cd68
    call Call_000_01bb
    ld a, [$d0e3]
    sub $c8
    ld b, $f6

jr_000_1b2c:
    sub $0a
    jr c, jr_000_1b33

    inc b
    jr jr_000_1b2c

jr_000_1b33:
    add $0a
    push af
    ld a, b
    ld [de], a
    inc de
    pop af
    ld b, $f6
    add b
    ld [de], a
    inc de
    ld a, $50
    ld [de], a
    pop af
    ld [$d0e3], a
    pop bc
    pop de
    pop hl
    ret


    call c, $9d2b
    adc e
    xor e
    swap e
    sbc $9d
    adc e
    xor e

Call_000_1b55:
    cp $c4
    jr c, jr_000_1b5c

    cp $c9
    ret


jr_000_1b5c:
    and a
    ret


Call_000_1b5e:
    ld hl, $1b67
    ld de, $0001
    jp Jump_000_3ddb


    rrca
    inc de
    add hl, sp
    ld b, [hl]
    sub h
    rst $38

Call_000_1b6d:
    push hl
    ld a, $02
    ld [$d093], a
    ld a, [$d0e3]
    ld [$d092], a
    ld a, $04
    ld [$d094], a

Jump_000_1b7e:
    call Call_000_37b3
    ld de, $cd68
    pop hl
    ret


Call_000_1b86:
Jump_000_1b86:
    ldh a, [$b8]
    push af
    ld a, [$d2dd]
    call Call_000_2ccd
    call Call_000_0167
    call Call_000_36ea

Call_000_1b95:
    call Call_000_26bb
    call Call_000_23ff
    call Call_000_0181
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_1ba5:
Jump_000_1ba5:
    ldh a, [$b8]
    push af
    ld a, [$d2dd]
    call Call_000_2ccd
    call Call_000_0167
    call Call_000_23ff
    call Call_000_0181
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_1bbe:
    ld hl, $d6ad
    res 4, [hl]
    ld b, $1c
    ld hl, $54fe
    jp Jump_000_3620


    and c
    ld b, d
    ld d, a
    ld b, e
    ld d, h
    ld b, l
    ld c, [hl]
    ld b, a
    inc l
    ld b, b
    sbc b
    ld c, c
    nop
    ld b, b
    and a
    ld c, e
    ld l, [hl]
    ld b, b
    ld e, $49
    and h
    ld c, c
    and h
    ld c, c
    ld sp, $2041
    ld b, b
    ld b, $42
    or b
    ld b, e
    and c
    ld b, l
    inc e
    ld b, b
    ld b, b
    ld b, b
    ld c, c
    ld b, c
    and [hl]
    ld b, [hl]
    ldh a, [rSCY]
    jp c, $8944

    ld b, [hl]
    inc l
    ld c, b
    cp c
    ld c, c
    ld c, b
    ld c, c
    or $4a
    ld b, b
    ld c, e
    ld d, h
    ld c, h
    sbc b
    ld c, [hl]
    pop af
    ld b, b
    rra
    ld d, b
    nop
    ld b, b
    ccf
    ld b, e
    add d
    ld b, [hl]
    sbc e
    ld b, a
    ld [hl], d
    ld b, c
    and h
    ld b, b
    ld [hl], c
    ld l, [hl]
    ld b, b
    ld b, l
    adc $45
    cp $55
    ld [hl], b
    ld d, a
    sbc $57
    call nc, $2f40
    ld l, d
    ld a, b
    ld l, a
    sbc d
    ld l, d
    inc h
    ld [hl], b
    db $ed
    ld [hl], b
    jr z, jr_000_1c8c

    db $eb
    ld b, b
    dec h
    ld b, l
    ld [hl], a
    ld b, [hl]
    or b
    ld e, b
    scf
    ld c, c
    ld l, l
    ld e, c
    inc d
    ld c, h
    ret nz

    ld [hl], b

Call_000_1c43:
    and a
    ld h, a
    xor l
    ld [hl], l
    jr jr_000_1ca3

    ld e, l
    ld e, e
    inc b
    ld c, l
    ld [$e14e], sp
    ld e, e
    adc d
    ld d, d
    ld a, e
    ld h, h

Jump_000_1c55:
    jr jr_000_1cb1

    jr jr_000_1cc4

    adc l
    ld [hl], c
    ld c, c

Jump_000_1c5c:
    ld [hl], d
    rst $10
    ld l, h
    db $d3
    ld [hl], c
    db $d3
    ld [hl], c
    sbc d
    ld l, l

Jump_000_1c65:
    ld a, [hl+]
    ld [hl], d
    adc l
    ld [hl], d
    ld h, c

Call_000_1c6a:
    ld l, [hl]
    inc hl
    ld l, a
    ld a, [hl-]
    ld h, [hl]
    jr nz, jr_000_1cba

    adc b
    ld l, a
    jp nc, $8066

    ld [hl], d
    adc b

Call_000_1c78:
    ld h, a
    rrca
    ld l, c
    ld h, d
    ld [hl], l
    inc e
    ld d, l
    ld b, e
    ld l, e
    ret z

    ld d, l
    and l
    ld d, [hl]
    ld e, h
    ld h, h
    dec de
    ld h, l
    cp h
    ld e, h
    ld [hl], b

jr_000_1c8c:
    ld e, [hl]
    inc c
    ld c, a
    adc [hl]
    ld h, d
    ld c, $63
    ldh a, [$64]
    daa
    ld h, a
    sub e
    ld l, c
    inc de
    ld l, l
    ld a, [bc]
    ld [hl], c
    inc a
    ld a, b
    inc a
    ld a, b
    inc a
    ld a, b

jr_000_1ca3:
    ld hl, sp+$76
    inc a
    ld a, b
    inc a

Jump_000_1ca8:
    ld a, b
    inc a
    ld a, b
    inc a
    ld a, b

Jump_000_1cad:
    inc a
    ld a, b
    inc a
    ld a, b

jr_000_1cb1:
    inc a
    ld a, b
    inc a
    ld a, b
    inc a
    ld a, b
    cp e
    ld a, e
    sbc c

jr_000_1cba:
    ld [hl], h
    db $76
    ld l, a
    cp l
    ld [hl], h
    ld d, a
    ld d, [hl]
    pop hl
    ld l, a
    ld a, [bc]

jr_000_1cc4:
    ld b, e
    jp hl


    ld b, l

Call_000_1cc7:
    add hl, de
    ld b, a
    jr c, jr_000_1d16

    call z, $d54b
    ld c, h
    scf
    ld c, l
    jr c, jr_000_1d22

    nop
    ld h, a
    sub c
    ld c, a
    ccf
    ld d, b
    pop de
    ld d, [hl]
    db $f4
    ld e, [hl]
    rla
    ld h, b
    bit 4, b
    or [hl]
    ld h, d
    sub l
    ld h, e
    ld b, e
    ld d, e
    jr nz, jr_000_1d2d

    add l
    ld b, l
    and $48
    cp a
    ld c, d
    ld [hl], d
    ld c, h
    ld d, $4f
    ccf
    ld d, d
    and l
    ld e, [hl]
    db $eb
    ld d, e
    ld l, l
    ld h, c
    and h

Call_000_1cfc:
    ld h, a
    add d
    ld c, a
    ld [hl], h
    ld d, b
    add hl, sp
    ld d, c
    jr jr_000_1d59

    ld d, c
    ld e, b
    ld [hl-], a
    ld e, a
    inc c

Jump_000_1d0a:
    ld [hl], d
    ld c, b
    ld [hl], e
    add h
    ld [hl], h
    sub b
    db $76
    add h
    ld l, [hl]
    call z, $9170

Jump_000_1d16:
jr_000_1d16:
    ld b, [hl]

Call_000_1d17:
    inc d
    ld h, b
    rra
    ld l, b
    jr z, jr_000_1d86

    cp [hl]
    ld l, c
    or e
    ld l, e
    ld c, c

jr_000_1d22:
    ld l, l
    ld hl, $216e
    ld l, [hl]
    ld l, d
    ld [hl], b
    and [hl]
    ld l, [hl]
    add a
    ld e, h

jr_000_1d2d:
    ld h, l
    ld e, a
    ld d, b
    ld h, h
    ld c, h
    ld l, b
    dec l
    ld l, l
    jp $d36d


    ld l, [hl]
    ld c, l
    ld l, c
    ld [bc], a
    ld l, e
    ld [hl], d
    ld l, e
    ld l, c
    ld l, h
    ld hl, $f66e
    ld [hl], d
    cp a
    ld [hl], l
    ld a, [$376e]
    ld [hl], b
    cp l
    ld c, l
    dec c
    ld [hl], h
    ld a, [$8363]
    ld l, c
    ld hl, $e170
    ld [hl], h
    adc c
    ld c, a

jr_000_1d59:
    cp [hl]
    ld d, d
    db $f4
    ld d, l
    ld a, [hl-]
    ld e, d
    ld [de], a
    ld e, l
    ld c, [hl]
    ld h, c

Call_000_1d63:
    ld c, [hl]
    ld h, c
    ld c, [hl]
    ld h, c

Call_000_1d67:
    ld c, [hl]
    ld h, c
    ret nc

    ld l, a
    or l
    ld [hl], e
    or e
    ld [hl], c
    sub d
    ld [hl], h
    call nz, $c378
    ld l, b
    ld c, h
    ld [hl], a
    ld c, h
    ld [hl], c
    jr z, jr_000_1def

    sub h
    db $76
    or l
    ld h, d
    dec sp
    ld h, h
    dec e
    ld a, h
    add sp, $66
    ld d, [hl]

jr_000_1d86:
    ld l, b
    inc h
    ld a, [hl]
    ret z

    ld l, b
    add c
    ld l, c

Jump_000_1d8d:
    ld [hl+], a
    ld l, d
    ld de, $f66b
    ld l, e
    db $ec
    ld c, c
    ld c, c

Call_000_1d96:
    ld h, d
    jp hl


    ld c, d
    ld l, c
    ld l, h
    ld a, [c]
    ld l, h
    ret z

    ld [hl], e
    ld b, e
    db $76
    ld l, l
    db $76
    ld a, [bc]
    ld h, d
    ret nc

    ld l, a
    ret nc

    ld l, a
    inc b
    ld a, l
    ld l, a

Call_000_1dac:
    ld a, l
    ret nc

    ld l, a
    ret nc

    ld l, a
    ret nc

    ld l, a
    ret nc

    ld l, a
    ld l, h
    ld [hl], l
    cp h
    ld [hl], a
    db $e4
    ld a, c

Call_000_1dbb:
    ld b, $1c
    ld hl, $4dea
    jp Jump_000_3620


Jump_000_1dc3:
    ld a, $ff
    ld [$cd66], a
    call Call_000_2c52
    ld b, $03
    ld hl, $497b
    call Call_000_3620
    ld hl, $d6ab
    bit 0, [hl]
    jr z, jr_000_1ddf

    ld a, $03
    ld [$d101], a

jr_000_1ddf:
    ld hl, $d6ad
    bit 5, [hl]
    res 5, [hl]
    call z, Call_000_2cf8
    call nz, Call_000_2336
    ld hl, $d6b1

jr_000_1def:
    ld a, [hl]
    and $18
    jr z, jr_000_1e01

    res 3, [hl]
    ld b, $1c
    ld hl, $4a61
    call Call_000_3620
    call Call_000_0ebd

jr_000_1e01:
    ld b, $03
    ld hl, $49d1
    call Call_000_3620
    ld hl, $d6ac
    res 5, [hl]
    call Call_000_0ebd
    ld hl, $d0eb
    set 5, [hl]
    set 6, [hl]
    xor a
    ld [$cd66], a

Jump_000_1e1c:
    call Call_000_0b31

Jump_000_1e1f:
    call Call_000_0b31
    call Call_000_0b3c
    ld a, [$d6b5]
    bit 6, a
    call nz, Call_000_1dbb
    ld a, [$cfac]
    and a
    jp nz, Jump_000_1fcc

    call Call_000_295e
    ld b, $07
    ld hl, $7a34
    call Call_000_3620
    ld a, [$d982]
    and a
    jp nz, Jump_000_2153

    ld hl, $d6ac
    bit 3, [hl]
    res 3, [hl]
    jp nz, Jump_000_2153

    ld a, [$d6b1]
    and $18
    jp nz, Jump_000_237c

    ld a, [$d036]
    and a
    jp nz, Jump_000_2043

    ld a, [$d6af]
    bit 7, a
    jr z, jr_000_1e6a

    ldh a, [$b4]
    jr jr_000_1e6c

jr_000_1e6a:
    ldh a, [$b3]

jr_000_1e6c:
    bit 3, a
    jr z, jr_000_1e76

    xor a
    ldh [$8c], a
    jp Jump_000_1e9a


jr_000_1e76:
    bit 0, a
    jp z, Jump_000_1f02

    ld a, [$d6af]
    bit 2, a
    jp nz, Jump_000_1ee4

    call Call_000_3145
    jr nz, jr_000_1eda

    call Call_000_3ee5
    ldh a, [$eb]
    and a
    jp z, Jump_000_1e1c

    call Call_000_253a
    ldh a, [$8c]
    and a
    jp z, Jump_000_1e1c

Jump_000_1e9a:
    ld a, $35
    call Call_000_3e9d
    call Call_000_0ebd
    ld a, [$cd5b]
    bit 2, a
    jr nz, jr_000_1eda

    bit 0, a
    jr nz, jr_000_1eda

    call Call_000_13f1
    ld a, [$cc47]
    and a
    jr z, jr_000_1eda

    dec a
    ld a, $00
    ld [$cc47], a
    jr z, jr_000_1ed7

    ld a, $52
    call Call_000_3e9d
    ld a, [$d2dd]
    ld [$d699], a
    call $6261
    ld a, [$d2dd]
    call Call_000_2ccd

Call_000_1ed2:
    ld hl, $d2e6
    set 7, [hl]

jr_000_1ed7:
    jp Jump_000_1dc3


jr_000_1eda:
    ld a, [$d036]
    and a
    jp nz, Jump_000_2043

    jp Jump_000_1e1c


Jump_000_1ee4:
jr_000_1ee4:
    ld hl, $cd5b
    res 2, [hl]
    call Call_000_0ebd
    ld a, $01
    ld [$cc4b], a
    ld a, [$d4a7]
    and a
    jp z, Jump_000_1e1c

    ld [$d4a8], a
    xor a
    ld [$d4a7], a
    jp Jump_000_1e1c


Jump_000_1f02:
    ldh a, [$b4]

Jump_000_1f04:
    bit 7, a
    jr z, jr_000_1f11

    ld a, $01
    ld [$c103], a
    ld a, $04
    jr jr_000_1f34

jr_000_1f11:
    bit 6, a
    jr z, jr_000_1f1e

    ld a, $ff
    ld [$c103], a
    ld a, $08
    jr jr_000_1f34

jr_000_1f1e:
    bit 5, a
    jr z, jr_000_1f2b

    ld a, $ff
    ld [$c105], a
    ld a, $02
    jr jr_000_1f34

jr_000_1f2b:
    bit 4, a
    jr z, jr_000_1ee4

    ld a, $01
    ld [$c105], a

jr_000_1f34:
    ld [$d4a9], a

Jump_000_1f37:
    ld a, [$d6af]
    bit 7, a
    jr nz, jr_000_1f95

    ld a, [$cc4b]
    and a
    jr z, jr_000_1f95

    ld a, [$d4a9]
    ld b, a
    ld a, [$d4a8]
    cp b
    jr z, jr_000_1f95

    swap a
    or b
    cp $48
    jr nz, jr_000_1f5c

    ld a, $02
    ld [$d4a7], a
    jr jr_000_1f7b

jr_000_1f5c:
    cp $84
    jr nz, jr_000_1f67

    ld a, $01

Jump_000_1f62:
    ld [$d4a7], a
    jr jr_000_1f7b

jr_000_1f67:
    cp $12
    jr nz, jr_000_1f72

    ld a, $04
    ld [$d4a7], a
    jr jr_000_1f7b

jr_000_1f72:
    cp $21
    jr nz, jr_000_1f7b

    ld a, $08
    ld [$d4a7], a

jr_000_1f7b:
    ld hl, $cd5b
    set 2, [hl]
    ld hl, $cc4b
    dec [hl]
    jr nz, jr_000_1f7b

    ld a, [$d4a9]
    ld [$d4a7], a
    call Call_000_209a

Jump_000_1f8f:
    jp c, Jump_000_204e

Jump_000_1f92:
    jp Jump_000_1e1c


jr_000_1f95:
    ld a, [$d4a9]
    ld [$d4a7], a
    call Call_000_0ebd
    ld a, [$d67f]
    cp $02
    jr z, jr_000_1fbf

    call Call_000_25e8
    jr nc, jr_000_1fc5

    push hl
    ld hl, $d6b5
    bit 2, [hl]
    pop hl
    jp z, Jump_000_1e1c

    push hl
    call Call_000_2300
    pop hl
    jp c, Jump_000_211d

    jp Jump_000_1e1c


jr_000_1fbf:
    call Call_000_29c8
    jp c, Jump_000_1e1c

jr_000_1fc5:
    ld a, $08
    ld [$cfac], a
    jr jr_000_1fde

Jump_000_1fcc:
    ld a, [$d6b5]
    bit 7, a
    jr z, jr_000_1fdb

    ld b, $11
    ld hl, $57b0
    call Call_000_3620

jr_000_1fdb:
    call Call_000_0ebd

jr_000_1fde:
    ld hl, $cd5b
    res 2, [hl]
    ld a, [$d67f]
    dec a
    jr nz, jr_000_1ff3

    ld a, [$d6b5]
    bit 6, a
    jr nz, jr_000_1ff3

    call Call_000_20b7

jr_000_1ff3:
    call Call_000_2738
    ld a, [$cfac]
    and a
    jp nz, Jump_000_21d1

    ld a, [$d6af]
    bit 7, a
    jr nz, jr_000_201a

    ld hl, $d100
    dec [hl]
    ld a, [$d6ab]
    bit 0, a
    jr z, jr_000_201a

    ld hl, $d101
    dec [hl]
    jr nz, jr_000_201a

    ld hl, $d6ab
    res 0, [hl]

jr_000_201a:
    ld a, [$d70f]
    bit 7, a
    jr z, jr_000_2030

    ld b, $07
    ld hl, $7a43
    call Call_000_3620
    ld a, [$d982]
    and a
    jp nz, Jump_000_2153

jr_000_2030:
    ld a, [$d034]
    and a
    jp nz, Jump_000_20cb

    ld a, $13
    call Call_000_3e9d
    ld a, [$d0f2]
    and a
    jp nz, Jump_000_2348

Jump_000_2043:
    call Call_000_209a
    ld hl, $d6b5
    res 2, [hl]
    jp nc, Jump_000_20cb

Jump_000_204e:
    ld hl, $d6ac

Jump_000_2051:
    res 6, [hl]
    ld hl, $d6b2
    res 3, [hl]
    ld hl, $d0eb
    set 5, [hl]
    set 6, [hl]
    xor a
    ldh [$b4], a
    ld a, [$d2dd]
    cp $a6
    jr nz, jr_000_206e

    ld hl, $d71a
    set 7, [hl]

jr_000_206e:
    ld hl, $d6ad
    set 5, [hl]
    ld a, [$d2dd]
    cp $28
    jp z, Jump_000_2087

    ld hl, $4ba3
    ld b, $0f
    call Call_000_3620
    ld a, d
    and a
    jr z, jr_000_208f

Jump_000_2087:
    ld c, $0a
    call Call_000_3781
    jp Jump_000_1dc3


jr_000_208f:
    ld a, $ff
    ld [$d034], a
    call Call_000_2a2c
    jp Jump_000_2348


Call_000_209a:
Jump_000_209a:
    ld a, [$d6ac]
    bit 4, a
    jr nz, jr_000_20b5

    call Call_000_3145
    jr nz, jr_000_20b5

    ld a, [$d6ad]
    bit 4, a
    jr nz, jr_000_20b5

    ld b, $0f
    ld hl, $7204
    jp Jump_000_3620


jr_000_20b5:
    and a
    ret


Call_000_20b7:
    ld a, [$cc57]
    and a
    ret nz

    ld a, [$d2dd]
    cp $1c

Call_000_20c1:
    jr nz, jr_000_20c8

    ldh a, [$b4]
    and $70
    ret nz

jr_000_20c8:
    jp Jump_000_2738


Jump_000_20cb:
    ld a, [$d32d]
    and a
    jp z, Jump_000_21d1

    ld a, [$d32d]
    ld b, $00
    ld c, a
    ld a, [$d2e0]
    ld d, a
    ld a, [$d2e1]
    ld e, a
    ld hl, $d32e

Jump_000_20e3:
    ld a, [hl+]
    cp d

Jump_000_20e5:
    jr nz, jr_000_2146

    ld a, [hl+]
    cp e
    jr nz, jr_000_2147

    push hl
    push bc
    ld hl, $d6b5
    set 2, [hl]
    ld b, $03
    ld hl, $4ae3
    call Call_000_3620
    pop bc
    pop hl
    jr c, jr_000_214c

    push hl
    push bc
    call Call_000_2300
    pop bc
    pop hl
    jr nc, jr_000_2147

    ld a, [$d6b2]
    bit 2, a
    jr nz, jr_000_214c

    push de
    push bc
    call Call_000_0153

Jump_000_2113:
    pop bc
    pop de
    ldh a, [$b4]
    and $f0
    jr z, jr_000_2147

    jr jr_000_214c

Jump_000_211d:
    ld a, [$d32d]
    ld c, a
    ld hl, $d32e

jr_000_2124:
    ld a, [hl+]

Jump_000_2125:
    ld b, a
    ld a, [$d2e0]
    cp b
    jr nz, jr_000_213d

    ld a, [hl+]
    ld b, a
    ld a, [$d2e1]
    cp b
    jr nz, jr_000_213e

    ld a, [hl+]
    ld [$d3ae], a
    ld a, [hl]
    ldh [$8b], a
    jr jr_000_2153

jr_000_213d:
    inc hl

jr_000_213e:
    inc hl
    inc hl
    dec c
    jr nz, jr_000_2124

    jp Jump_000_1e1c


jr_000_2146:
    inc hl

jr_000_2147:
    inc hl
    inc hl
    jp Jump_000_21cc


jr_000_214c:
    ld a, [hl+]
    ld [$d3ae], a
    ld a, [hl+]
    ldh [$8b], a

Jump_000_2153:
jr_000_2153:
    ld a, [$d32d]
    sub c
    ld [$d6ba], a
    ld a, [$d2dd]
    ld [$d6bb], a
    call Call_000_22f8
    jr nz, jr_000_2187

    ld a, [$d2dd]
    ld [$d2e4], a
    ld a, [$d2e8]
    ld [$d2e5], a
    ldh a, [$8b]
    ld [$d2dd], a
    cp $52
    jr nz, jr_000_2182

    ld a, $06
    ld [$d2dc], a
    call Call_000_0b71

jr_000_2182:
    call Call_000_22e0

Jump_000_2185:
    jr jr_000_21c1

jr_000_2187:
    ldh a, [$8b]
    cp $ff
    jr z, jr_000_21b4

    ld [$d2dd], a
    ld b, $1c
    ld hl, $4cd8

Call_000_2195:
    call Call_000_3620
    ld a, [$cd51]

Call_000_219b:
    dec a
    jr nz, jr_000_21a8

    ld hl, $d6b1
    set 3, [hl]
    call Call_000_23a6
    jr jr_000_21ab

jr_000_21a8:
    call Call_000_22e0

jr_000_21ab:
    ld hl, $d6b5
    res 0, [hl]
    res 1, [hl]
    jr jr_000_21c1

jr_000_21b4:
    ld a, [$d2e4]

Call_000_21b7:
    ld [$d2dd], a
    call Call_000_22e0
    xor a
    ld [$d2dc], a

Call_000_21c1:
jr_000_21c1:
    ld hl, $d6b5
    set 0, [hl]

Jump_000_21c6:
    call Call_000_2ceb
    jp Jump_000_1dc3


Jump_000_21cc:
    inc b
    dec c
    jp nz, Jump_000_20e3

Jump_000_21d1:
    ld a, [$d2e1]
    cp $ff
    jr nz, jr_000_2215

    ld a, [$d306]
    ld [$d2dd], a
    ld a, [$d30e]
    ld [$d2e1], a

Jump_000_21e4:
    ld a, [$d2e0]
    ld c, a
    ld a, [$d30d]
    add c
    ld c, a
    ld [$d2e0], a
    ld a, [$d30f]
    ld l, a
    ld a, [$d310]
    ld h, a
    srl c
    jr z, jr_000_220a

jr_000_21fc:
    ld a, [$d30c]
    add $06
    ld e, a
    ld d, $00
    ld b, $00

Jump_000_2206:
    add hl, de

Jump_000_2207:
    dec c
    jr nz, jr_000_21fc

jr_000_220a:
    ld a, l
    ld [$d2de], a
    ld a, h

Jump_000_220f:
    ld [$d2df], a

Call_000_2212:
    jp Jump_000_22c4


jr_000_2215:
    ld b, a
    ld a, [$d4a4]
    cp b
    jr nz, jr_000_2259

    ld a, [$d311]
    ld [$d2dd], a

Jump_000_2222:
    ld a, [$d319]
    ld [$d2e1], a
    ld a, [$d2e0]

Jump_000_222b:
    ld c, a

Call_000_222c:
    ld a, [$d318]
    add c
    ld c, a
    ld [$d2e0], a
    ld a, [$d31a]
    ld l, a
    ld a, [$d31b]
    ld h, a
    srl c
    jr z, jr_000_224e

jr_000_2240:
    ld a, [$d317]
    add $06
    ld e, a
    ld d, $00
    ld b, $00
    add hl, de
    dec c
    jr nz, jr_000_2240

jr_000_224e:
    ld a, l
    ld [$d2de], a
    ld a, h
    ld [$d2df], a
    jp Jump_000_22c4


jr_000_2259:
    ld a, [$d2e0]
    cp $ff
    jr nz, jr_000_2290

    ld a, [$d2f0]
    ld [$d2dd], a
    ld a, [$d2f7]
    ld [$d2e0], a
    ld a, [$d2e1]
    ld c, a
    ld a, [$d2f8]
    add c
    ld c, a
    ld [$d2e1], a
    ld a, [$d2f9]
    ld l, a
    ld a, [$d2fa]
    ld h, a
    ld b, $00
    srl c
    add hl, bc
    ld a, l
    ld [$d2de], a
    ld a, h
    ld [$d2df], a
    jp Jump_000_22c4


jr_000_2290:
    ld b, a
    ld a, [$d4a3]
    cp b
    jr nz, jr_000_22dd

    ld a, [$d2fb]
    ld [$d2dd], a
    ld a, [$d302]
    ld [$d2e0], a
    ld a, [$d2e1]
    ld c, a
    ld a, [$d303]
    add c
    ld c, a
    ld [$d2e1], a
    ld a, [$d304]

Call_000_22b2:
    ld l, a
    ld a, [$d305]
    ld h, a
    ld b, $00
    srl c
    add hl, bc
    ld a, l
    ld [$d2de], a
    ld a, h
    ld [$d2df], a

Jump_000_22c4:
    call Call_000_2a8d
    call Call_000_0da6
    ld b, $09
    call Call_000_3e1f
    ld b, $05
    ld hl, $7840
    call Call_000_3620
    call Call_000_2413
    jp Jump_000_1e1f


jr_000_22dd:
    jp Jump_000_1e1c


Call_000_22e0:
    ld a, [$c448]
    cp $0b
    jr nz, jr_000_22eb

    ld a, $ad
    jr jr_000_22ed

jr_000_22eb:
    ld a, $b5

Call_000_22ed:
jr_000_22ed:
    call Call_000_0e45
    ld a, [$d2dc]
    and a
    ret nz

    jp Jump_000_0b71


Call_000_22f8:
    ld a, [$d2e6]
    and a
    ret z

    cp $17
    ret


Call_000_2300:
    ld a, [$d2dd]
    cp $61
    jr z, jr_000_2329

    cp $c7
    jr z, jr_000_232e

    cp $c8
    jr z, jr_000_232e

    cp $ca
    jr z, jr_000_232e

    cp $52
    jr z, jr_000_232e

    ld a, [$d2e6]
    and a
    jr z, jr_000_232e

    cp $0d
    jr z, jr_000_232e

    cp $0e
    jr z, jr_000_232e

    cp $17

Call_000_2327:
    jr z, jr_000_232e

jr_000_2329:
    ld hl, $4a45
    jr jr_000_2331

jr_000_232e:
    ld hl, $4a94

jr_000_2331:
    ld b, $03

Jump_000_2333:
    jp Jump_000_3620


Call_000_2336:
    ld b, $03
    ld hl, $49a5
    call Call_000_3620
    ld a, [$d2dc]

Jump_000_2341:
    and a
    jp z, Jump_000_0b78

    jp Jump_000_0b3c


Jump_000_2348:
    call Call_000_0b71
    ld a, $08
    call Call_000_2368
    ld hl, $d6ad

Call_000_2353:
    res 5, [hl]
    ld a, $01
    ldh [$b8], a
    ld [$2000], a

Jump_000_235c:
    call $7560
    call $6261

Call_000_2362:
    call Call_000_0da6
    jp $5bb7


Call_000_2368:
    ld [$cfae], a
    ld a, $ff
    ld [$c0ee], a

Call_000_2370:
    call Call_000_0e45

jr_000_2373:
    ld a, [$cfae]
    and a
    jr nz, jr_000_2373

    jp Jump_000_0a96


Jump_000_237c:
    call Call_000_0ebd
    call Call_000_3e07
    xor a
    ld [$cf06], a
    ld [$d67f], a
    ld [$d034], a
    ld [$d2dc], a
    ld hl, $d6b1
    set 2, [hl]
    res 5, [hl]
    call Call_000_23a6
    ld a, $01
    ldh [$b8], a
    ld [$2000], a
    call $6261
    jp $5bb7


Call_000_23a6:
    ld b, $1c
    ld hl, $4b0b
    jp Jump_000_3620


Call_000_23ae:
Jump_000_23ae:
    ld a, [$d67f]
    dec a
    jr z, jr_000_23bb

    ldh a, [$d7]
    and a

Call_000_23b7:
    jr nz, jr_000_23ca

    jr jr_000_23c0

jr_000_23bb:
    call Call_000_23dc
    jr c, jr_000_23ca

Call_000_23c0:
jr_000_23c0:
    xor a

Call_000_23c1:
    ld [$d67f], a

Call_000_23c4:
    ld [$d0df], a

Call_000_23c7:
    jp Jump_000_2a5e


jr_000_23ca:
    ld a, [$d67f]
    and a
    jp z, Jump_000_2a5e

    dec a
    jp z, Jump_000_2a6e

Call_000_23d5:
    dec a
    jp z, Jump_000_2a66

    jp Jump_000_2a5e


Call_000_23dc:
    ld a, [$d2dd]
    cp $22
    jr z, jr_000_23f7

Jump_000_23e3:
    cp $09

Jump_000_23e5:
    jr z, jr_000_23f7

    ld a, [$d2e6]
    ld b, a
    ld hl, $23f9

jr_000_23ee:
    ld a, [hl+]
    cp b
    jr z, jr_000_23f7

    inc a
    jr nz, jr_000_23ee

    and a
    ret


jr_000_23f7:
    scf
    ret


Jump_000_23f9:
    nop
    inc bc
    dec bc
    ld c, $11
    rst $38

Call_000_23ff:
    ld a, [$d4ad]
    ld l, a
    ld a, [$d4ae]

Jump_000_2406:
    ld h, a
    ld de, $9000
    ld bc, $0600
    ld a, [$d4aa]
    jp Jump_000_028c


Call_000_2413:
    ld hl, $c6e8
    ld a, [$d32c]
    ld d, a
    ld bc, $0514

jr_000_241d:
    ld a, d
    ld [hl+], a
    dec bc
    ld a, c
    or b
    jr nz, jr_000_241d

    ld hl, $c6e8
    ld a, [$d2e8]
    ldh [$8c], a

Jump_000_242c:
    add $06
    ldh [$8b], a
    ld b, $00
    ld c, a
    add hl, bc
    add hl, bc
    add hl, bc
    ld c, $03
    add hl, bc
    ld a, [$d2e9]

Call_000_243c:
    ld e, a
    ld a, [$d2ea]
    ld d, a
    ld a, [$d2e7]
    ld b, a

jr_000_2445:
    push hl
    ldh a, [$8c]
    ld c, a

jr_000_2449:
    ld a, [de]
    inc de
    ld [hl+], a
    dec c
    jr nz, jr_000_2449

    pop hl
    ldh a, [$8b]
    add l
    ld l, a
    jr nc, jr_000_2457

    inc h

jr_000_2457:
    dec b
    jr nz, jr_000_2445

    ld a, [$d2f0]
    cp $ff
    jr z, jr_000_2481

    call Call_000_2ccd
    ld a, [$d2f1]
    ld l, a
    ld a, [$d2f2]
    ld h, a
    ld a, [$d2f3]
    ld e, a
    ld a, [$d2f4]
    ld d, a

Call_000_2474:
    ld a, [$d2f5]
    ldh [$8b], a
    ld a, [$d2f6]
    ldh [$8c], a
    call Call_000_24f5

jr_000_2481:
    ld a, [$d2fb]
    cp $ff
    jr z, jr_000_24a8

    call Call_000_2ccd
    ld a, [$d2fc]
    ld l, a
    ld a, [$d2fd]
    ld h, a
    ld a, [$d2fe]
    ld e, a
    ld a, [$d2ff]
    ld d, a
    ld a, [$d300]
    ldh [$8b], a
    ld a, [$d301]
    ldh [$8c], a
    call Call_000_24f5

jr_000_24a8:
    ld a, [$d306]
    cp $ff
    jr z, jr_000_24ce

Jump_000_24af:
    call Call_000_2ccd
    ld a, [$d307]
    ld l, a
    ld a, [$d308]
    ld h, a
    ld a, [$d309]
    ld e, a
    ld a, [$d30a]
    ld d, a

Jump_000_24c2:
    ld a, [$d30b]
    ld b, a
    ld a, [$d30c]
    ldh [$8b], a
    call Call_000_2519

jr_000_24ce:
    ld a, [$d311]
    cp $ff
    jr z, jr_000_24f4

    call Call_000_2ccd
    ld a, [$d312]
    ld l, a
    ld a, [$d313]
    ld h, a
    ld a, [$d314]
    ld e, a
    ld a, [$d315]
    ld d, a

Jump_000_24e8:
    ld a, [$d316]
    ld b, a
    ld a, [$d317]
    ldh [$8b], a
    call Call_000_2519

jr_000_24f4:
    ret


Call_000_24f5:
    ld c, $03

jr_000_24f7:
    push de
    push hl
    ldh a, [$8b]
    ld b, a

jr_000_24fc:
    ld a, [hl+]
    ld [de], a
    inc de
    dec b
    jr nz, jr_000_24fc

    pop hl
    pop de
    ldh a, [$8c]
    add l
    ld l, a
    jr nc, jr_000_250b

Jump_000_250a:
    inc h

jr_000_250b:
    ld a, [$d2e8]
    add $06
    add e
    ld e, a
    jr nc, jr_000_2515

    inc d

jr_000_2515:
    dec c
    jr nz, jr_000_24f7

    ret


Call_000_2519:
jr_000_2519:
    push hl
    push de
    ld c, $03

jr_000_251d:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_000_251d

    pop de
    pop hl

Jump_000_2525:
    ldh a, [$8b]
    add l
    ld l, a
    jr nc, jr_000_252c

    inc h

Jump_000_252c:
jr_000_252c:
    ld a, [$d2e8]
    add $06
    add e
    ld e, a
    jr nc, jr_000_2536

    inc d

jr_000_2536:
    dec b
    jr nz, jr_000_2519

    ret


Call_000_253a:
    xor a
    ldh [$8c], a
    ld a, [$d42f]
    and a
    jr z, jr_000_256f

    ld a, $35
    call Call_000_3e9d
    ld hl, $d430
    ld a, [$d42f]
    ld b, a
    ld c, $00

jr_000_2551:
    inc c
    ld a, [hl+]
    cp d

Call_000_2554:
    jr z, jr_000_2559

    inc hl
    jr jr_000_256c

jr_000_2559:
    ld a, [hl+]
    cp e
    jr nz, jr_000_256c

    push hl
    push bc
    ld hl, $d450
    ld b, $00
    dec c
    add hl, bc
    ld a, [hl]
    ldh [$8c], a

Call_000_2569:
    pop bc
    pop hl
    ret


jr_000_256c:
    dec b
    jr nz, jr_000_2551

jr_000_256f:
    ld a, $35
    call Call_000_3e9d
    ld hl, $d4b1
    ld b, $03
    ld d, $20

jr_000_257b:
    ld a, [hl+]
    cp c
    jr z, jr_000_2584

    dec b
    jr nz, jr_000_257b

Call_000_2582:
    ld d, $10

Call_000_2584:
jr_000_2584:
    ld bc, $3c40
    ld a, [$c109]
    cp $04
    jr nz, jr_000_2595

    ld a, b
    sub d
    ld b, a
    ld a, $08
    jr jr_000_25b0

Jump_000_2595:
jr_000_2595:
    cp $00

Call_000_2597:
    jr nz, jr_000_25a0

    ld a, b
    add d
    ld b, a
    ld a, $04
    jr jr_000_25b0

jr_000_25a0:
    cp $0c
    jr nz, jr_000_25ab

    ld a, c

Call_000_25a5:
    add d
    ld c, a
    ld a, $01
    jr jr_000_25b0

jr_000_25ab:
    ld a, c
    sub d
    ld c, a
    ld a, $02

jr_000_25b0:
    ld [$d4a9], a
    ld a, [$d460]

Call_000_25b6:
    and a
    ret z

    ld hl, $c110
    ld d, a
    ld e, $01

jr_000_25be:
    push hl
    ld a, [hl+]
    and a

Call_000_25c1:
    jr z, jr_000_25d2

    inc l
    ld a, [hl+]
    inc a
    jr z, jr_000_25d2

    inc l
    ld a, [hl+]
    cp b
    jr nz, jr_000_25d2

    inc l
    ld a, [hl]
    cp c
    jr z, jr_000_25dc

jr_000_25d2:
    pop hl
    ld a, l
    add $10
    ld l, a
    inc e

Call_000_25d8:
    dec d
    jr nz, jr_000_25be

    ret


jr_000_25dc:
    pop hl
    ld a, l

Jump_000_25de:
    and $f0
    inc a
    ld l, a
    set 7, [hl]
    ld a, e
    ldh [$8c], a
    ret


Call_000_25e8:
    ld a, [$d6b5]
    bit 6, a
    jr nz, jr_000_2625

    ld a, [$cd38]
    and a
    jr nz, jr_000_2625

    ld a, [$d4a9]
    ld d, a
    ld a, [$c10c]
    and d

Jump_000_25fd:
    jr nz, jr_000_2617

    xor a
    ldh [$8c], a
    call Call_000_2582
    ldh a, [$8c]
    and a
    jr nz, jr_000_2617

Call_000_260a:
    ld hl, $268f
    call Call_000_2641
    jr c, jr_000_2617

    call Call_000_2627
    jr nc, jr_000_2625

jr_000_2617:
    ld a, [$c02a]
    cp $b4
    jr z, jr_000_2623

    ld a, $b4
    call Call_000_0e45

jr_000_2623:
    scf
    ret


jr_000_2625:
    and a
    ret


Call_000_2627:
    ld a, $35
    call Call_000_3e9d

Call_000_262c:
    ld a, [$cfad]
    ld c, a
    ld hl, $d4af
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_000_2636:
    ld a, [hl+]
    cp $ff
    jr z, jr_000_263f

    cp c
    ret z

    jr jr_000_2636

jr_000_263f:
    scf
    ret


Call_000_2641:
    push hl
    ld a, $35
    call Call_000_3e9d
    push de
    push bc
    ld b, $06
    ld hl, $7f2a

Call_000_264e:
    call Call_000_3620
    pop bc
    pop de
    pop hl
    and a
    ld a, [$d6b5]
    bit 6, a
    ret nz

Call_000_265b:
    ld a, [$cfad]
    ld c, a

jr_000_265f:
    ld a, [$d2e6]
    ld b, a
    ld a, [hl+]
    cp $ff
    jr z, jr_000_268d

    cp b
    jr z, jr_000_266f

    inc hl

jr_000_266c:
    inc hl
    jr jr_000_265f

jr_000_266f:
    ld a, [$c45c]
    ld b, a
    ld a, [hl]
    cp b
    jr z, jr_000_267e

    inc hl
    ld a, [hl]
    cp b
    jr z, jr_000_2685

    jr jr_000_266c

jr_000_267e:
    inc hl

Jump_000_267f:
    ld a, [hl]
    cp c
    jr z, jr_000_268b

    jr jr_000_265f

jr_000_2685:
    dec hl
    ld a, [hl+]
    cp c
    inc hl
    jr nz, jr_000_265f

jr_000_268b:
    scf
    ret


jr_000_268d:
    and a
    ret


    ld de, $0520
    ld de, $0541
    inc bc
    jr nc, jr_000_26c6

    ld de, $052a
    ld de, $2105

Jump_000_269e:
    inc bc
    ld d, d
    ld l, $03
    ld d, l
    ld l, $03

Jump_000_26a5:
    ld d, [hl]
    ld l, $03
    jr nz, jr_000_26d8

    inc bc
    ld e, [hl]
    ld l, $03
    ld e, a
    ld l, $ff
    inc bc

Call_000_26b2:
Jump_000_26b2:
    inc d

Call_000_26b3:
Jump_000_26b3:
    ld l, $03
    ld c, b

Call_000_26b6:
    ld l, $11
    inc d

Call_000_26b9:
    dec b

Call_000_26ba:
    rst $38

Call_000_26bb:
    ldh a, [$b8]

Call_000_26bd:
    push af
    ld a, [$d4aa]
    ldh [$b8], a
    ld [$2000], a

jr_000_26c6:
    ld a, [$d2de]

Call_000_26c9:
Jump_000_26c9:
    ld e, a
    ld a, [$d2df]
    ld d, a
    ld hl, $c508
    ld b, $05

jr_000_26d3:
    push hl
    push de
    ld c, $06

jr_000_26d7:
    push bc

Call_000_26d8:
Jump_000_26d8:
jr_000_26d8:
    push de

Jump_000_26d9:
    push hl
    ld a, [de]
    ld c, a
    call Call_000_292e
    pop hl
    pop de
    pop bc
    inc hl
    inc hl
    inc hl
    inc hl
    inc de
    dec c
    jr nz, jr_000_26d7

    pop de
    ld a, [$d2e8]
    add $06
    add e
    ld e, a
    jr nc, jr_000_26f5

    inc d

jr_000_26f5:
    pop hl
    ld a, $60
    add l
    ld l, a
    jr nc, jr_000_26fd

    inc h

jr_000_26fd:
    dec b
    jr nz, jr_000_26d3

    ld hl, $c508
    ld bc, $0000

Jump_000_2706:
    ld a, [$d2e2]
    and a
    jr z, jr_000_2710

    ld bc, $0030
    add hl, bc

jr_000_2710:
    ld a, [$d2e3]
    and a
    jr z, jr_000_271a

    ld bc, $0002
    add hl, bc

jr_000_271a:
    ld de, $c3a0
    ld b, $12

jr_000_271f:
    ld c, $14

jr_000_2721:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_000_2721

Call_000_2727:
    ld a, $04
    add l
    ld l, a
    jr nc, jr_000_272e

    inc h

jr_000_272e:
    dec b
    jr nz, jr_000_271f

    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_2738:
Jump_000_2738:
    ld a, [$c103]
    ld b, a
    ld a, [$c105]
    ld c, a
    ld hl, $cfac
    dec [hl]
    jr nz, jr_000_2754

    ld a, [$d2e0]
    add b
    ld [$d2e0], a
    ld a, [$d2e1]
    add c
    ld [$d2e1], a

jr_000_2754:
    ld a, [$cfac]
    cp $07
    jp nz, Jump_000_2847

    ld a, c
    cp $01
    jr nz, jr_000_2773

    ld a, [$d4a5]
    ld e, a
    and $e0
    ld d, a
    ld a, e
    add $02
    and $1f
    or d
    ld [$d4a5], a
    jr jr_000_27be

jr_000_2773:
    cp $ff

Call_000_2775:
    jr nz, jr_000_2789

    ld a, [$d4a5]
    ld e, a
    and $e0
    ld d, a
    ld a, e

Jump_000_277f:
    sub $02
    and $1f
    or d
    ld [$d4a5], a
    jr jr_000_27be

jr_000_2789:
    ld a, b
    cp $01
    jr nz, jr_000_27a5

    ld a, [$d4a5]
    add $40
    ld [$d4a5], a
    jr nc, jr_000_27be

    ld a, [$d4a6]
    inc a
    and $03
    or $98

Call_000_27a0:
    ld [$d4a6], a
    jr jr_000_27be

jr_000_27a5:
    cp $ff
    jr nz, jr_000_27be

    ld a, [$d4a5]
    sub $40
    ld [$d4a5], a
    jr nc, jr_000_27be

Call_000_27b3:
    ld a, [$d4a6]
    dec a

Call_000_27b7:
    and $03
    or $98

Jump_000_27bb:
    ld [$d4a6], a

jr_000_27be:
    ld a, c
    and a
    jr z, jr_000_27c2

jr_000_27c2:
    ld hl, $d2e3
    ld a, [hl]
    add c

Call_000_27c7:
    ld [hl], a

Jump_000_27c8:
    cp $02
    jr nz, jr_000_27da

    xor a
    ld [hl], a
    ld hl, $d462
    inc [hl]
    ld de, $d2de
    call Call_000_2876
    jr jr_000_281c

jr_000_27da:
    cp $ff
    jr nz, jr_000_27ed

    ld a, $01
    ld [hl], a
    ld hl, $d462
    dec [hl]

Jump_000_27e5:
    ld de, $d2de
    call Call_000_2880
    jr jr_000_281c

jr_000_27ed:
    ld hl, $d2e2
    ld a, [hl]
    add b
    ld [hl], a
    cp $02
    jr nz, jr_000_2808

    xor a
    ld [hl], a
    ld hl, $d461
    inc [hl]
    ld de, $d2de
    ld a, [$d2e8]
    call Call_000_288a

Call_000_2806:
    jr jr_000_281c

jr_000_2808:
    cp $ff
    jr nz, jr_000_281c

    ld a, $01

Jump_000_280e:
    ld [hl], a
    ld hl, $d461
    dec [hl]
    ld de, $d2de
    ld a, [$d2e8]
    call Call_000_2896

jr_000_281c:
    call Call_000_26bb
    ld a, [$c103]

Call_000_2822:
    cp $01
    jr nz, jr_000_282b

    call Call_000_28c3
    jr jr_000_2847

jr_000_282b:
    cp $ff
    jr nz, jr_000_2834

    call Call_000_28a2
    jr jr_000_2847

jr_000_2834:
    ld a, [$c105]
    cp $01
    jr nz, jr_000_2840

    call Call_000_28e4
    jr jr_000_2847

jr_000_2840:
    cp $ff
    jr nz, jr_000_2847

Call_000_2844:
    call Call_000_2919

Jump_000_2847:
jr_000_2847:
    ld a, [$c103]
    ld b, a
    ld a, [$c105]
    ld c, a

Jump_000_284f:
    sla b
    sla c
    ldh a, [$af]
    add b
    ldh [$af], a
    ldh a, [$ae]
    add c
    ldh [$ae], a
    ld hl, $c114
    ld a, [$d460]
    and a
    jr z, jr_000_2875

    ld e, a

Call_000_2867:
jr_000_2867:
    ld a, [hl]
    sub b
    ld [hl+], a
    inc l
    ld a, [hl]

Jump_000_286c:
    sub c
    ld [hl], a
    ld a, $0e
    add l
    ld l, a
    dec e
    jr nz, jr_000_2867

jr_000_2875:
    ret


Call_000_2876:
    ld a, [de]
    add $01
    ld [de], a
    ret nc

    inc de
    ld a, [de]
    inc a
    ld [de], a
    ret


Call_000_2880:
    ld a, [de]
    sub $01
    ld [de], a

Call_000_2884:
    ret nc

    inc de
    ld a, [de]
    dec a
    ld [de], a
    ret


Call_000_288a:
    add $06
    ld b, a
    ld a, [de]
    add b
    ld [de], a
    ret nc

    inc de
    ld a, [de]
    inc a
    ld [de], a
    ret


Call_000_2896:
    add $06
    ld b, a
    ld a, [de]
    sub b
    ld [de], a
    ret nc

    inc de
    ld a, [de]
    dec a
    ld [de], a
    ret


Call_000_28a2:
    ld hl, $c3a0
    call Call_000_28b7
    ld a, [$d4a5]
    ldh [$d1], a
    ld a, [$d4a6]
    ldh [$d2], a
    ld a, $02
    ldh [$d0], a
    ret


Call_000_28b7:
    ld de, $cbfc
    ld c, $28

jr_000_28bc:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_000_28bc

    ret


Call_000_28c3:
    ld hl, $c4e0
    call Call_000_28b7
    ld a, [$d4a5]

Call_000_28cc:
    ld l, a
    ld a, [$d4a6]
    ld h, a
    ld bc, $0200
    add hl, bc
    ld a, h
    and $03
    or $98
    ldh [$d2], a
    ld a, l
    ldh [$d1], a
    ld a, $02
    ldh [$d0], a
    ret


Call_000_28e4:
    ld hl, $c3b2
    call Call_000_2903
    ld a, [$d4a5]
    ld c, a
    and $e0
    ld b, a
    ld a, c
    add $12

Jump_000_28f4:
    and $1f
    or b
    ldh [$d1], a
    ld a, [$d4a6]
    ldh [$d2], a
    ld a, $01
    ldh [$d0], a
    ret


Call_000_2903:
    ld de, $cbfc
    ld c, $12

jr_000_2908:
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    inc de
    ld a, $13
    add l
    ld l, a
    jr nc, jr_000_2915

    inc h

jr_000_2915:
    dec c
    jr nz, jr_000_2908

    ret


Call_000_2919:
    ld hl, $c3a0
    call Call_000_2903
    ld a, [$d4a5]

Jump_000_2922:
    ldh [$d1], a
    ld a, [$d4a6]
    ldh [$d2], a
    ld a, $01
    ldh [$d0], a
    ret


Call_000_292e:
    push hl
    ld a, [$d4ab]
    ld l, a
    ld a, [$d4ac]
    ld h, a
    ld a, c
    swap a
    ld b, a

Call_000_293b:
    and $f0
    ld c, a
    ld a, b
    and $0f
    ld b, a
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    ld c, $04

jr_000_2948:
    push bc
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl+], a
    inc de

Jump_000_294f:
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl], a
    inc de

Jump_000_2955:
    ld bc, $0015

Jump_000_2958:
    add hl, bc
    pop bc
    dec c
    jr nz, jr_000_2948

    ret


Call_000_295e:
    xor a
    ld [$c103], a
    ld [$c105], a
    call Call_000_2a2c

Jump_000_2968:
    call Call_000_0153
    ld a, [$d6b2]
    bit 3, a
    jr nz, jr_000_2983

    ld a, [$d2dd]
    cp $1c
    jr nz, jr_000_2983

    ldh a, [$b4]
    and $f3
    jr nz, jr_000_2983

Jump_000_297f:
    ld a, $80
    ldh [$b4], a

jr_000_2983:
    ld a, [$d6af]
    bit 7, a
    ret z

    ldh a, [$b4]
    ld b, a
    ld a, [$cd3b]
    and b
    ret nz

    ld hl, $cd38

Jump_000_2994:
    dec [hl]
    ld a, [hl]
    cp $ff

Call_000_2998:
    jr z, jr_000_29ac

    ld hl, $ccd3

Jump_000_299d:
    add l
    ld l, a
    jr nc, jr_000_29a2

    inc h

jr_000_29a2:
    ld a, [hl]
    ldh [$b4], a
    and a
    ret nz

    ldh [$b3], a

Jump_000_29a9:
    ldh [$b2], a
    ret


jr_000_29ac:
    xor a
    ld [$cd3a], a
    ld [$cd38], a
    ld [$ccd3], a

Jump_000_29b6:
    ld [$cd66], a
    ldh [$b4], a
    ld hl, $d6b5
    ld a, [hl]
    and $f8
    ld [hl], a
    ld hl, $d6af
    res 7, [hl]

Call_000_29c7:
    ret


Call_000_29c8:
    ld a, [$d6af]
    bit 7, a
    jp nz, Jump_000_2a15

    ld a, [$d4a9]
    ld d, a
    ld a, [$c10c]
    and d
    jr nz, jr_000_29f6

    ld hl, $26b1
    call Call_000_2641
    jr c, jr_000_2a06

    ld a, $35
    call Call_000_3e9d

Call_000_29e7:
    ld a, [$cfad]
    cp $14
    jr z, jr_000_2a15

    cp $32
    jr z, jr_000_2a23

    cp $48
    jr z, jr_000_2a15

jr_000_29f6:
    ld hl, $d4af
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_000_29fc:
    ld a, [hl+]
    cp $ff
    jr z, jr_000_2a06

    cp c
    jr z, jr_000_2a17

    jr jr_000_29fc

Jump_000_2a06:
jr_000_2a06:
    ld a, [$c02a]
    cp $b4
    jr z, jr_000_2a12

Call_000_2a0d:
    ld a, $b4
    call Call_000_0e45

jr_000_2a12:
    scf
    jr jr_000_2a16

Jump_000_2a15:
jr_000_2a15:
    and a

jr_000_2a16:
    ret


jr_000_2a17:
    xor a
    ld [$d67f], a
    call Call_000_23ae
    call Call_000_0d9b
    jr jr_000_2a15

jr_000_2a23:
    ld a, [$d2e6]
    cp $0e

Call_000_2a28:
    jr nz, jr_000_2a15

    jr jr_000_2a17

Call_000_2a2c:
Jump_000_2a2c:
    push hl
    push de
    push bc
    ld b, $03
    ld hl, $7557
    call Call_000_3620
    ld a, [$cd5b]
    bit 1, a
    jr z, jr_000_2a46

    ld b, $03
    ld hl, $75e7
    call Call_000_3620

jr_000_2a46:
    pop bc
    pop de
    pop hl
    call Call_000_3156
    ld a, [$d2dd]

Jump_000_2a4f:
    call Call_000_2ccd
    ld hl, $d2ed
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $2a5d
    push de
    jp hl


    ret


Jump_000_2a5e:
    ld de, $4180
    ld hl, $8000
    jr jr_000_2a74

Jump_000_2a66:
    ld de, $76c0
    ld hl, $8000
    jr jr_000_2a74

Jump_000_2a6e:
    ld de, $4000
    ld hl, $8000

jr_000_2a74:
    push de
    push hl
    ld bc, $050c
    call Call_000_02dd
    pop hl
    pop de
    ld a, $c0
    add e
    ld e, a
    jr nc, jr_000_2a85

    inc d

jr_000_2a85:
    set 3, h
    ld bc, $050c

Jump_000_2a8a:
    jp Jump_000_02dd


Call_000_2a8d:
    ld b, $03
    ld hl, $7445
    call Call_000_3620
    ld a, [$d2e6]
    ld [$d0de], a
    ld a, [$d2dd]
    call Call_000_2ccd
    ld a, [$d2e6]
    ld b, a
    res 7, a
    ld [$d2e6], a
    ldh [$8b], a
    bit 7, b
    ret nz

    ld hl, $1bcb
    ld a, [$d2dd]
    sla a
    jr nc, jr_000_2aba

    inc h

jr_000_2aba:
    add l
    ld l, a
    jr nc, jr_000_2abf

    inc h

jr_000_2abf:
    ld a, [hl+]

Call_000_2ac0:
    ld h, [hl]

Jump_000_2ac1:
    ld l, a
    ld de, $d2e6
    ld c, $0a

jr_000_2ac7:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_000_2ac7

    ld a, $ff
    ld [$d2f0], a
    ld [$d2fb], a
    ld [$d306], a

Jump_000_2ad8:
    ld [$d311], a
    ld a, [$d2ef]

Jump_000_2ade:
    ld b, a
    bit 3, b
    jr z, jr_000_2ae9

    ld de, $d2f0
    call Call_000_2c49

jr_000_2ae9:
    bit 2, b
    jr z, jr_000_2af3

    ld de, $d2fb
    call Call_000_2c49

jr_000_2af3:
    bit 1, b
    jr z, jr_000_2afd

    ld de, $d306
    call Call_000_2c49

jr_000_2afd:
    bit 0, b
    jr z, jr_000_2b07

    ld de, $d311
    call Call_000_2c49

jr_000_2b07:
    ld a, [hl+]
    ld [$d328], a
    ld a, [hl+]
    ld [$d329], a
    push hl
    ld a, [$d328]
    ld l, a
    ld a, [$d329]
    ld h, a
    ld de, $d32c
    ld a, [hl+]
    ld [de], a
    ld a, [hl+]
    ld [$d32d], a
    and a
    jr z, jr_000_2b33

    ld c, a
    ld de, $d32e

jr_000_2b28:
    ld b, $04

jr_000_2b2a:
    ld a, [hl+]
    ld [de], a
    inc de
    dec b
    jr nz, jr_000_2b2a

    dec c
    jr nz, jr_000_2b28

jr_000_2b33:
    ld a, [hl+]
    ld [$d42f], a
    and a
    jr z, jr_000_2b61

    ld c, a
    ld de, $d450
    ld a, d
    ldh [$95], a
    ld a, e
    ldh [$96], a

Call_000_2b44:
    ld de, $d430

jr_000_2b47:
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    push de
    ldh a, [$95]
    ld d, a
    ldh a, [$96]
    ld e, a

Call_000_2b54:
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, d
    ldh [$95], a
    ld a, e
    ldh [$96], a
    pop de
    dec c
    jr nz, jr_000_2b47

jr_000_2b61:
    ld a, [$d6ad]
    bit 5, a

Jump_000_2b66:
    jp nz, Jump_000_2c09

    ld a, [hl+]
    ld [$d460], a
    push hl
    ld hl, $c110
    ld de, $c210
    xor a
    ld b, $f0

jr_000_2b77:
    ld [hl+], a
    ld [de], a
    inc e
    dec b
    jr nz, jr_000_2b77

    ld hl, $c112
    ld de, $0010
    ld c, $0f

jr_000_2b85:
    ld [hl], $ff
    add hl, de
    dec c
    jr nz, jr_000_2b85

    pop hl
    ld de, $c110
    ld a, [$d460]
    and a
    jp z, Jump_000_2c09

    ld b, a
    ld c, $00

Jump_000_2b99:
    ld a, [hl+]
    ld [de], a
    inc d
    ld a, $04
    add e
    ld e, a
    ld a, [hl+]
    ld [de], a
    inc e

Jump_000_2ba3:
    ld a, [hl+]
    ld [de], a
    inc e
    ld a, [hl+]
    ld [de], a
    ld a, [hl+]
    ldh [$8d], a
    ld a, [hl+]
    ldh [$8e], a
    push bc
    push hl
    ld b, $00
    ld hl, $d463
    add hl, bc
    ldh a, [$8d]
    ld [hl+], a
    ldh a, [$8e]
    ld [hl], a
    ldh a, [$8e]
    ldh [$8d], a

Call_000_2bc0:
    and $3f
    ld [hl], a
    pop hl
    ldh a, [$8d]
    bit 6, a
    jr nz, jr_000_2bd0

    bit 7, a
    jr nz, jr_000_2be4

    jr jr_000_2bf4

jr_000_2bd0:
    ld a, [hl+]
    ldh [$8d], a

Call_000_2bd3:
    ld a, [hl+]
    ldh [$8e], a
    push hl
    ld hl, $d483
    add hl, bc
    ldh a, [$8d]
    ld [hl+], a
    ldh a, [$8e]
    ld [hl], a
    pop hl
    jr jr_000_2bfd

jr_000_2be4:
    ld a, [hl+]
    ldh [$8d], a
    push hl
    ld hl, $d483
    add hl, bc
    ldh a, [$8d]
    ld [hl+], a
    xor a
    ld [hl], a
    pop hl
    jr jr_000_2bfd

jr_000_2bf4:
    push hl
    ld hl, $d483
    add hl, bc
    xor a
    ld [hl+], a
    ld [hl], a
    pop hl

jr_000_2bfd:
    pop bc
    dec d
    ld a, $0a
    add e
    ld e, a
    inc c
    inc c
    dec b
    jp nz, Jump_000_2b99

Jump_000_2c09:
    ld a, $19
    call Call_000_3e9d
    ld hl, $4f2e
    ld b, $03
    call Call_000_3620
    pop hl
    ld a, [$d2e7]
    add a
    ld [$d4a3], a
    ld a, [$d2e8]
    add a
    ld [$d4a4], a
    ld a, [$d2dd]
    ld c, a
    ld b, $00
    ldh a, [$b8]

Jump_000_2c2d:
    push af
    ld a, $03
    ldh [$b8], a
    ld [$2000], a
    ld hl, $4693
    add hl, bc
    add hl, bc

Call_000_2c3a:
    ld a, [hl+]
    ld [$d2da], a
    ld a, [hl]

Call_000_2c3f:
    ld [$d2db], a
    pop af

Jump_000_2c43:
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_2c49:
    ld c, $0b

jr_000_2c4b:
    ld a, [hl+]
    ld [de], a
    inc de

Call_000_2c4e:
    dec c

Jump_000_2c4f:
    jr nz, jr_000_2c4b

Call_000_2c51:
    ret


Call_000_2c52:
    ldh a, [$b8]
    push af

Call_000_2c55:
Jump_000_2c55:
    call Call_000_0167
    ld a, $98
    ld [$d4a6], a
    xor a
    ld [$d4a5], a
    ldh [$af], a
    ldh [$ae], a
    ld [$cfac], a
    ld [$d0de], a
    ld [$d0df], a
    ld [$d327], a
    call Call_000_36ea
    call Call_000_2a8d
    ld b, $05
    ld hl, $7840
    call Call_000_3620

Call_000_2c7f:
Jump_000_2c7f:
    call Call_000_2413
    call Call_000_23ff
    call Call_000_26bb
    ld hl, $c3a0
    ld de, $9800
    ld b, $12

jr_000_2c90:
    ld c, $14

jr_000_2c92:
    ld a, [hl+]
    ld [de], a
    inc e
    dec c
    jr nz, jr_000_2c92

    ld a, $0c
    add e
    ld e, a
    jr nc, jr_000_2c9f

    inc d

jr_000_2c9f:
    dec b
    jr nz, jr_000_2c90

    ld a, $01
    ld [$cfb2], a
    call Call_000_0181
    ld b, $09
    call Call_000_3e1f
    call Call_000_23ae

Jump_000_2cb2:
    ld a, [$d6b1]
    and $18
    jr nz, jr_000_2cc6

Call_000_2cb9:
    ld a, [$d6b2]
    bit 1, a
    jr nz, jr_000_2cc6

    call Call_000_0df3
    call Call_000_0da6

jr_000_2cc6:
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_2ccd:
    push hl
    push bc
    ld c, a
    ld b, $00
    ld a, $03
    call Call_000_3606
    ld hl, $4883
    add hl, bc
    ld a, [hl]
    ldh [$e8], a

Jump_000_2cde:
    call Call_000_3617
    ldh a, [$e8]
    ldh [$b8], a
    ld [$2000], a
    pop bc
    pop hl
    ret


Call_000_2ceb:
    ld a, $1e
    ld [$d0ff], a
    ld hl, $d6af
    ld a, [hl]
    or $26
    ld [hl], a
    ret


Call_000_2cf8:
    ld hl, $d6a7
    res 0, [hl]
    ret


Jump_000_2cfe:
    ld b, $05
    ld hl, $23ae
    call Call_000_3620
    jp Jump_000_0d9b


Call_000_2d09:
    ld b, a
    ldh a, [$b8]
    push af

Jump_000_2d0d:
    ld a, [$cf0d]
    ldh [$b8], a
    ld [$2000], a

Call_000_2d15:
    ld a, b
    add a
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld bc, $0004
    ld de, $d2de
    call Call_000_01bb
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_2d2c:
    push hl
    push de
    push bc
    ld a, $71
    ld [hl+], a
    ld a, $62
    ld [hl+], a
    push hl
    ld a, $63

jr_000_2d38:
    ld [hl+], a
    dec d
    jr nz, jr_000_2d38

    ld a, [$cf7b]
    dec a
    ld a, $6d
    jr z, jr_000_2d45

    dec a

jr_000_2d45:
    ld [hl], a

Call_000_2d46:
    pop hl
    ld a, e
    and a
    jr nz, jr_000_2d51

Jump_000_2d4b:
    ld a, c
    and a
    jr z, jr_000_2d64

Jump_000_2d4f:
    ld e, $01

jr_000_2d51:
    ld a, e
    sub $08
    jr c, jr_000_2d60

    ld e, a
    ld a, $6b
    ld [hl+], a
    ld a, e
    and a
    jr z, jr_000_2d64

    jr jr_000_2d51

jr_000_2d60:
    ld a, $63
    add e
    ld [hl], a

jr_000_2d64:
    pop bc
    pop de
    pop hl
    ret


Call_000_2d68:
    ld hl, $75c2
    ld b, $01
    jp Jump_000_3620


    ld hl, $d0b9
    ld e, b
    ld d, $00
    add hl, de
    ld a, c
    ld [hl], a
    ret


Call_000_2d7a:
Jump_000_2d7a:
    ld a, $01
    ld [$d087], a

Call_000_2d7f:
Jump_000_2d7f:
    push hl
    ld a, [$d0e3]
    push af
    ld a, [$cf78]
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld hl, $d0e3
    ld a, [hl]
    pop bc

Jump_000_2d94:
    ld [hl], b
    and a
    pop hl
    jr z, jr_000_2d9d

    cp $98
    jr c, jr_000_2da3

jr_000_2d9d:
    ld a, $01
    ld [$cf78], a
    ret


jr_000_2da3:
    push hl

Jump_000_2da4:
    ld de, $9000
    call Call_000_3034
    pop hl
    ldh a, [$b8]
    push af
    ld a, $0f

Call_000_2db0:
    ldh [$b8], a
    ld [$2000], a
    xor a
    ld [$ffe1], a
    call $73c5
    xor a
    ld [$d087], a
    pop af

Call_000_2dc1:
    ldh [$b8], a
    ld [$2000], a

Jump_000_2dc6:
    ret


Call_000_2dc7:
Jump_000_2dc7:
    call Call_000_2dd0
    call Call_000_0e45
    jp Jump_000_3790


Call_000_2dd0:
    dec a
    ld c, a
    ld b, $00
    ld hl, $541e
    add hl, bc

Call_000_2dd8:
    add hl, bc
    add hl, bc

Jump_000_2dda:
    ld a, $0e
    call Call_000_3606
    ld a, [hl+]
    ld b, a
    ld a, [hl+]
    ld [$c0f1], a
    ld a, [hl]
    ld [$c0f2], a
    call Call_000_3617
    ld a, b
    ld c, $14
    rlca
    add b
    add c
    ret


Call_000_2df3:
    ldh a, [$d7]
    push af
    xor a
    ldh [$d7], a
    call Call_000_3e04
    call Call_000_0188
    call Call_000_2e17
    call Call_000_2ecb
    jp Jump_000_2e51


Call_000_2e08:
    ldh a, [$d7]
    push af
    xor a
    ldh [$d7], a
    call Call_000_2e17

Call_000_2e11:
    call Call_000_2ed0
    jp Jump_000_2e51


Call_000_2e17:
    ld a, $01
    call Call_000_3606
    call Call_000_370a
    ld hl, $d6af
    set 6, [hl]
    xor a
    ld [$cc49], a
    ld [$cc37], a
    ld hl, $cc24
    inc a
    ld [hl+], a
    xor a
    ld [hl+], a
    ld a, [$cc2b]
    push af
    ld [hl+], a
    inc hl
    ld a, [$d123]
    and a
    jr z, jr_000_2e3f

    dec a

jr_000_2e3f:
    ld [hl+], a
    ld a, [$d0e4]
    and a
    ld a, $03
    jr z, jr_000_2e4d

    xor a
    ld [$d0e4], a
    inc a

jr_000_2e4d:
    ld [hl+], a

Call_000_2e4e:
    pop af

Jump_000_2e4f:
    ld [hl], a

Call_000_2e50:
    ret


Jump_000_2e51:
jr_000_2e51:
    ld a, $01
    ld [$cc4a], a
    ld a, $40
    ld [$d078], a
    call Call_000_3b0c

Call_000_2e5e:
    call Call_000_3c1c
    ld b, a
    xor a
    ld [$d078], a
    ld a, [$cc26]
    ld [$cc2b], a
    ld hl, $d6af
    res 6, [hl]
    ld a, [$cc35]
    and a
    jp nz, Jump_000_2ea3

    pop af
    ldh [$d7], a
    bit 1, b
    jr nz, jr_000_2e9e

Jump_000_2e7f:
    ld a, [$d123]
    and a
    jr z, jr_000_2e9e

    ld a, [$cc26]
    ld [$cf79], a
    ld hl, $d124
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    ld [$cf78], a
    ld [$cfc0], a
    call Call_000_3617
    and a
    ret


jr_000_2e9e:
    call Call_000_3617
    scf
    ret


Jump_000_2ea3:
    bit 1, b
    jr z, jr_000_2ebb

    ld b, $04
    ld hl, $5dd1
    call Call_000_3620
    xor a
    ld [$cc35], a
    ld [$d05a], a
    call Call_000_2ed0
    jr jr_000_2e51

jr_000_2ebb:
    ld a, [$cc26]
    ld [$cf79], a
    ld b, $04
    ld hl, $6116
    call Call_000_3620
    jr jr_000_2e51

Call_000_2ecb:
    ld hl, $7a0c
    jr jr_000_2ed3

Call_000_2ed0:
    ld hl, $7a1d

jr_000_2ed3:
    ld b, $04
    jp Jump_000_3620


Call_000_2ed8:
Jump_000_2ed8:
    push de

Jump_000_2ed9:
    dec de
    dec de
    ld a, [de]
    ld b, a
    dec de
    ld a, [de]
    or b
    pop de
    jr nz, jr_000_2eed

    ld a, $a4
    ld [hl+], a
    ld a, $a9
    ld [hl+], a
    ld [hl], $a5
    and a
    ret


Call_000_2eed:
jr_000_2eed:
    ldh a, [$b8]
    push af
    ld a, $2f
    ldh [$b8], a
    ld [$2000], a
    call $4000
    pop bc
    ld a, b
    ldh [$b8], a
    ld [$2000], a

Jump_000_2f01:
    ret


Call_000_2f02:
    ld a, $6e
    ld [hl+], a
    ld c, $02

Call_000_2f07:
    ld a, [$cfa0]
    cp $64
    jr c, jr_000_2f1a

    dec hl
    inc c

Call_000_2f10:
    jr jr_000_2f1a

    ld a, $6e
    ld [hl+], a
    ld c, $03
    ld a, [$cfa0]

Call_000_2f1a:
jr_000_2f1a:
    ld [$d0e3], a
    ld de, $d0e3
    ld b, $41
    jp Jump_000_3c8f


    ld hl, $d0b9
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ret


Call_000_2f2e:
    ldh a, [$b8]

Jump_000_2f30:
    push af
    ld a, $0e
    ldh [$b8], a
    ld [$2000], a
    push bc
    push de
    push hl
    ld a, [$d0e3]
    push af
    ld a, [$d092]
    ld [$d0e3], a
    ld de, $64c7
    ld b, $66
    cp $b6
    jr z, jr_000_2f7f

    ld de, $67ad
    cp $b8
    jr z, jr_000_2f7f

    ld de, $6624
    ld b, $77
    cp $b7
    jr z, jr_000_2f7f

    cp $15

Call_000_2f60:
    jr z, jr_000_2f89

    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld bc, $001c
    ld hl, $4000
    call Call_000_3ad1
    ld de, $d095
    ld bc, $001c
    call Call_000_01bb
    jr jr_000_2f97

jr_000_2f7f:
    ld hl, $d09f
    ld [hl], b
    inc hl
    ld [hl], e
    inc hl
    ld [hl], d
    jr jr_000_2f97

jr_000_2f89:
    ld hl, $4200

Call_000_2f8c:
    ld de, $d095
    ld bc, $001c
    ld a, $01
    call Call_000_01a3

jr_000_2f97:
    ld a, [$d092]
    ld [$d095], a
    pop af
    ld [$d0e3], a
    pop hl
    pop de
    pop bc
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_2fab:
    ld a, [$cf79]
    ld hl, $d257

Call_000_2fb1:
    push hl
    push bc
    call Call_000_3ac7
    ld de, $cd68
    push de
    ld bc, $0006

Call_000_2fbd:
    call Call_000_01bb

Jump_000_2fc0:
    pop de
    pop bc
    pop hl
    ret


Call_000_2fc4:
Jump_000_2fc4:
    ld b, c
    res 7, c
    res 6, c

jr_000_2fc9:
    ld a, [de]
    swap a
    call Call_000_2fe7
    ld a, [de]
    call Call_000_2fe7
    inc de
    dec c

Jump_000_2fd5:
    jr nz, jr_000_2fc9

    bit 7, b

Call_000_2fd9:
Jump_000_2fd9:
    jr z, jr_000_2fe6

    bit 6, b
    jr nz, jr_000_2fe0

Call_000_2fdf:
    dec hl

jr_000_2fe0:
    ld [hl], $f6
    call Call_000_391d
    inc hl

jr_000_2fe6:
    ret


Call_000_2fe7:
    and $0f
    and a
    jr z, jr_000_2ff4

    res 7, b

jr_000_2fee:
    add $f6
    ld [hl+], a
    jp Jump_000_391d


jr_000_2ff4:
    bit 7, b
    jr z, jr_000_2fee

    bit 6, b
    ret nz

    inc hl
    ret


Call_000_2ffd:
    ld bc, $d095
    add hl, bc
    ld a, [hl+]
    ld [$d088], a
    ld a, [hl]
    ld [$d089], a
    ld a, [$cf78]
    ld b, a
    cp $15
    ld a, $01
    jr z, jr_000_3031

    ld a, b
    cp $1f

Jump_000_3016:
    ld a, $09
    jr c, jr_000_3031

    ld a, b
    cp $4a
    ld a, $0a
    jr c, jr_000_3031

    ld a, b
    cp $75
    ld a, $0b

Call_000_3026:
    jr c, jr_000_3031

    ld a, b
    cp $9a

Call_000_302b:
    ld a, $0c

Jump_000_302d:
    jr c, jr_000_3031

    ld a, $0d

jr_000_3031:
    jp Jump_000_0fce


Call_000_3034:
    push de
    ld hl, $000b
    call Call_000_2ffd

Call_000_303b:
    ld hl, $d09f
    ld a, [hl+]
    ld c, a

Jump_000_3040:
    pop de

Call_000_3041:
Jump_000_3041:
    push de
    and $0f
    ldh [$8b], a
    ld b, a
    ld a, $07
    sub b
    inc a
    srl a
    ld b, a
    add a

Call_000_304f:
Jump_000_304f:
    add a
    add a
    sub b

Call_000_3052:
    ldh [$8d], a

Call_000_3054:
    ld a, c

Call_000_3055:
Jump_000_3055:
    swap a
    and $0f
    ld b, a
    add a
    add a
    add a
    ldh [$8c], a
    ld a, $07

Jump_000_3061:
    sub b
    ld b, a
    ldh a, [$8d]
    add b
    add a
    add a
    add a
    ldh [$8d], a
    xor a
    ld [$4000], a
    ld hl, $a000
    call Call_000_30ae
    ld de, $a188
    ld hl, $a000
    call Call_000_3091
    ld hl, $a188
    call Call_000_30ae
    ld de, $a310
    ld hl, $a188
    call Call_000_3091
    pop de
    jp Jump_000_30b9


Call_000_3091:
    ldh a, [$8d]
    ld b, $00

Call_000_3095:
    ld c, a
    add hl, bc
    ldh a, [$8b]

Call_000_3099:
jr_000_3099:
    push af
    push hl
    ldh a, [$8c]
    ld c, a

jr_000_309e:
    ld a, [de]
    inc de
    ld [hl+], a
    dec c
    jr nz, jr_000_309e

    pop hl
    ld bc, $0038
    add hl, bc
    pop af

Jump_000_30aa:
    dec a
    jr nz, jr_000_3099

    ret


Call_000_30ae:
    ld bc, $0188

jr_000_30b1:
    xor a
    ld [hl+], a
    dec bc
    ld a, b
    or c
    jr nz, jr_000_30b1

Jump_000_30b8:
    ret


Call_000_30b9:
Jump_000_30b9:
    xor a

Call_000_30ba:
    ld [$4000], a
    push de
    ld hl, $a497
    ld de, $a30f
    ld bc, $a187
    ld a, $c4
    ldh [$8b], a

jr_000_30cb:
    ld a, [de]
    dec de
    ld [hl-], a
    ld a, [bc]
    dec bc
    ld [hl-], a
    ld a, [de]
    dec de

Call_000_30d3:
    ld [hl-], a
    ld a, [bc]
    dec bc
    ld [hl-], a
    ldh a, [$8b]

Call_000_30d9:
    dec a
    ldh [$8b], a
    jr nz, jr_000_30cb

Call_000_30de:
Jump_000_30de:
    ld a, [$d087]
    and a
    jr z, jr_000_30f2

    ld bc, $0310
    ld hl, $a188

jr_000_30ea:
    swap [hl]
    inc hl
    dec bc
    ld a, b
    or c
    jr nz, jr_000_30ea

jr_000_30f2:
    pop hl
    ld de, $a188
    ld c, $31
    ldh a, [$b8]
    ld b, a
    jp Jump_000_02dd


Call_000_30fe:
    ld a, $01
    ld [$cc3c], a
    ret


Call_000_3104:
    ld b, $03
    ld hl, $563d
    jp Jump_000_3620


Call_000_310c:
    ldh a, [$b8]
    push af
    ld a, $03

Call_000_3111:
    ldh [$b8], a
    ld [$2000], a
    call $69c4
    pop de
    ld a, d
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3121:
    push hl
    push de
    push bc

Call_000_3124:
    ld b, $03

Call_000_3126:
    ld hl, $6a6f
    call Call_000_3620
    pop bc
    pop de
    pop hl
    ret


Call_000_3130:
Jump_000_3130:
    ldh a, [$b8]
    push af
    ld a, $01
    ldh [$b8], a
    ld [$2000], a
    call $766d
    pop bc
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3145:
    ld a, [$cc57]
    and a
    ret nz

    ld a, [$d6b5]
    bit 1, a
    ret nz

    ld a, [$d6af]
    and $80
    ret


Call_000_3156:
    ld hl, $d6b5
    bit 0, [hl]

Jump_000_315b:
    res 0, [hl]
    jr nz, jr_000_318e

    ld a, [$cc57]
    and a
    ret z

    dec a
    add a
    ld d, $00
    ld e, a
    ld hl, $3188
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ldh a, [$b8]
    push af
    ld a, [$cc58]
    ldh [$b8], a
    ld [$2000], a
    ld a, [$cf0b]
    call Call_000_3dc7
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


    ld a, [$c87c]
    ld a, l
    dec [hl]
    ld a, [hl]

jr_000_318e:
    ld b, $06
    ld hl, $7c98
    jp Jump_000_3620


Jump_000_3196:
    ld b, $06
    ld hl, $7cd5
    jp Jump_000_3620


    ret


Call_000_319f:
    ld a, h
    ld [$d973], a
    ld a, l
    ld [$d974], a
    ret


Call_000_31a8:
    push af
    push de
    call Call_000_319f
    pop hl
    pop af
    push hl
    ld hl, $d6b2
    bit 4, [hl]
    res 4, [hl]
    jr z, jr_000_31bc

    ld a, [$d97c]

jr_000_31bc:
    pop hl
    ld [$d97c], a
    call Call_000_3dc7
    ld a, [$d97c]
    ret


Call_000_31c7:
Jump_000_31c7:
    push de

Call_000_31c8:
    ld de, $cf59
    ld bc, $0005
    call Call_000_01bb
    pop hl
    ld de, $cf5e
    ld bc, $0006
    jp Jump_000_01bb


Call_000_31db:
    push de
    push af
    ld d, $00
    ld e, a
    ld hl, $d973
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    add hl, de
    pop af
    and a
    jr nz, jr_000_31f1

    ld a, [hl]
    ld [$cc55], a
    jr jr_000_320d

jr_000_31f1:
    cp $02
    jr z, jr_000_320a

    cp $04
    jr z, jr_000_320a

    cp $06
    jr z, jr_000_320a

    cp $08
    jr z, jr_000_320a

    cp $0a
    jr nz, jr_000_320d

    ld a, [hl+]
    ld d, [hl]
    ld e, a

Jump_000_3208:
    jr jr_000_320d

jr_000_320a:
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_000_320d:
    pop de
    ret


Call_000_320f:
    ld a, $10

Call_000_3211:
    jp Jump_000_3e9d


Call_000_3214:
    call Call_000_319f
    xor a
    call Call_000_31db
    ld a, $02
    call Call_000_31db
    ld a, [$cc55]
    ld c, a
    ld b, $02
    call Call_000_320f
    ld a, c
    and a
    jr z, jr_000_3235

    ld a, $06
    call Call_000_31db
    jp Jump_000_3c79


jr_000_3235:
    ld a, $04
    call Call_000_31db
    call Call_000_3c79
    ld a, $0a
    call Call_000_31db
    push de
    ld a, $08
    call Call_000_31db
    pop de
    call Call_000_339c
    ld hl, $d6b2
    set 4, [hl]
    ld hl, $cd5b
    bit 0, [hl]
    ret nz

    call Call_000_33b2
    ld hl, $d97c
    inc [hl]
    jp Jump_000_32a5


Call_000_3261:
Jump_000_3261:
    call Call_000_334e
    ld a, [$cf0e]
    cp $ff
    jr nz, jr_000_3273

    xor a
    ld [$cf0e], a
    ld [$cc55], a
    ret


jr_000_3273:
    ld hl, $d6b2
    set 3, [hl]

Jump_000_3278:
    ld [$cd4f], a
    xor a
    ld [$cd50], a
    ld a, $4c
    call Call_000_3e9d
    ld a, $f0
    ld [$cd66], a
    xor a
    ldh [$b4], a
    call Call_000_3317
    ld hl, $d97c
    inc [hl]
    ret


    ld a, [$d6af]

Call_000_3297:
    and $01
    ret nz

    ld [$cd66], a
    ld a, [$cf0e]
    ldh [$8c], a
    call Call_000_13f1

Jump_000_32a5:
    xor a
    ld [$cd66], a
    call Call_000_331f
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $d6ad
    set 1, [hl]
    ld hl, $d97c
    inc [hl]
    ret


Call_000_32bd:
    ld hl, $d0eb
    set 5, [hl]
    set 6, [hl]
    ld hl, $d6ac
    res 7, [hl]
    ld hl, $cd5b
    res 0, [hl]
    ld a, [$d034]
    cp $ff
    jp z, Jump_000_3309

    ld a, $02
    call Call_000_31db
    ld a, [$cc55]
    ld c, a
    ld b, $01
    call Call_000_320f
    ld a, [$d692]
    cp $c8
    jr nc, jr_000_3301

    ld hl, $d54d
    ld de, $0002
    ld a, [$cf0e]
    call Call_000_3ddb
    inc hl
    ld a, [hl]
    ld [$cc4d], a
    ld a, $11

Call_000_32fe:
    call Call_000_3e9d

jr_000_3301:
    ld hl, $d6af
    bit 4, [hl]
    res 4, [hl]
    ret nz

Jump_000_3309:
    xor a
    ld [$cd66], a
    ldh [$b4], a
    ldh [$b3], a
    ldh [$b2], a
    ld [$d97c], a

Jump_000_3316:
    ret


Call_000_3317:
    ld b, $15
    ld hl, $7e2b
    jp Jump_000_3620


Call_000_331f:
    ld a, [$cd2d]
    ld [$d036], a
    ld [$d692], a
    cp $c8
    ld a, [$cd2e]
    jr c, jr_000_3333

    ld [$d03a], a
    ret


jr_000_3333:
    ld [$d0ec], a
    ret


Call_000_3337:
    ld hl, $7da3
    jr jr_000_3349

Call_000_333c:
    ld hl, $7dc3
    jr jr_000_3349

Call_000_3341:
Jump_000_3341:
    ld hl, $7de7
    jr jr_000_3349

Call_000_3346:
    ld hl, $7e07

jr_000_3349:
    ld b, $15
    jp Jump_000_3620


Call_000_334e:
    xor a

Jump_000_334f:
    call Call_000_31db
    ld d, h
    ld e, l

jr_000_3354:
    call Call_000_319f
    ld a, [de]
    ld [$cf0e], a
    ld [$cc55], a
    cp $ff
    ret z

    ld a, $02
    call Call_000_31db
    ld b, $02
    ld a, [$cc55]
    ld c, a
    call Call_000_320f
    ld a, c
    and a
    jr nz, jr_000_3394

    push hl
    push de
    push hl
    xor a
    call Call_000_31db

Call_000_337a:
    inc hl
    ld a, [hl]
    pop hl
    ld [$cd3e], a
    ld a, [$cf0e]
    swap a

Jump_000_3385:
    ld [$cd3d], a
    ld a, $39

Call_000_338a:
    call Call_000_3e9d
    pop de
    pop hl
    ld a, [$cd3d]
    and a
    ret nz

jr_000_3394:
    ld hl, $000c

Call_000_3397:
    add hl, de
    ld d, h
    ld e, l
    jr jr_000_3354

Call_000_339c:
    ldh a, [$b8]
    ld [$d06f], a
    ld a, h
    ld [$d069], a
    ld a, l
    ld [$d06a], a
    ld a, d

Jump_000_33aa:
    ld [$d06b], a
    ld a, e
    ld [$d06c], a
    ret


Call_000_33b2:
Jump_000_33b2:
    ld hl, $d483

Call_000_33b5:
    ld d, $00

Call_000_33b7:
    ld a, [$cf0e]
    dec a
    add a
    ld e, a
    add hl, de
    ld a, [hl+]
    ld [$cd2d], a

Call_000_33c2:
Jump_000_33c2:
    ld a, [hl]
    ld [$cd2e], a
    jp Jump_000_3432


Call_000_33c9:
Jump_000_33c9:
    push hl
    ld hl, $d6ac
    bit 7, [hl]

Call_000_33cf:
Jump_000_33cf:
    res 7, [hl]
    pop hl
    ret z

    ldh a, [$b8]
    push af
    ld a, [$d06f]
    ldh [$b8], a
    ld [$2000], a

Call_000_33de:
    push hl
    ld b, $09
    ld hl, $7eb2

Jump_000_33e4:
    call Call_000_3620
    ld hl, $3417
    call Call_000_3c79
    pop hl
    pop af
    ldh [$b8], a
    ld [$2000], a
    ld b, $06
    ld hl, $7e9f
    call Call_000_3620
    jp Jump_000_3790


    ld a, [$cf06]
    and a
    jr nz, jr_000_340e

    ld a, [$d069]

Call_000_3408:
    ld h, a
    ld a, [$d06a]
    ld l, a
    ret


jr_000_340e:
    ld a, [$d06b]

Jump_000_3411:
    ld h, a
    ld a, [$d06c]
    ld l, a
    ret


    nop
    ld a, a

Jump_000_3419:
    ld a, a
    ld a, a
    ld a, a
    ld d, b
    ld [$ffcd], sp
    inc sp
    call Call_000_3c89
    jp Jump_000_0f6a


    ld a, [$cd5b]
    bit 0, a
    ret nz

    call Call_000_33b2
    xor a
    ret


Jump_000_3432:
    ld a, [$cd2d]
    cp $e1
    ret z

    cp $f2
    ret z

    cp $f3
    ret z

    ld a, [$d039]
    and a
    ret nz

    xor a
    ld [$cfae], a
    ld a, $ff
    call Call_000_0e45
    ld a, $1f

Jump_000_344e:
    ld [$c0ef], a
    ld [$c0f0], a
    ld a, [$cd2d]
    ld b, a
    ld hl, $3483

jr_000_345b:
    ld a, [hl+]
    cp $ff
    jr z, jr_000_3467

    cp b
    jr nz, jr_000_345b

    ld a, $f6
    jr jr_000_3478

jr_000_3467:
    ld hl, $347e

jr_000_346a:
    ld a, [hl+]
    cp $ff
    jr z, jr_000_3476

    cp b
    jr nz, jr_000_346a

    ld a, $f9
    jr jr_000_3478

jr_000_3476:
    ld a, $fc

jr_000_3478:
    ld [$c0ee], a
    jp Jump_000_0e45


    set 1, [hl]
    jp c, $ffe8

    push de
    reti


    call c, $e3dd
    db $e4
    push hl
    and $ff

Call_000_348c:
jr_000_348c:
    ld a, [hl+]
    cp $ff
    ret z

    cp b
    jr nz, jr_000_34a5

    ld a, [hl+]
    cp c
    jr nz, jr_000_34a6

    ld a, [hl+]
    ld d, [hl]
    ld e, a
    ld hl, $ccd3
    call Call_000_3556
    dec a
    ld [$cd38], a
    ret


jr_000_34a5:
    inc hl

jr_000_34a6:
    inc hl
    inc hl
    jr jr_000_348c

Jump_000_34aa:
    call Call_000_373e
    ld b, $01
    ld hl, $7bf9
    jr jr_000_34c3

Jump_000_34b4:
    call Call_000_373e

Call_000_34b7:
    ld b, $08

Call_000_34b9:
    ld hl, $40ef
    jr jr_000_34c3

Jump_000_34be:
    ld b, $14
    ld hl, $7ab3

jr_000_34c3:
    call Call_000_3620
    jp Jump_000_14b1


Jump_000_34c9:
    ld b, $05
    ld hl, $7e34
    jr jr_000_34c3

Call_000_34d0:
Jump_000_34d0:
    xor a
    ld [$cd3b], a
    ld [$c206], a
    ld hl, $d6af
    set 7, [hl]

Call_000_34dc:
    ret


Call_000_34dd:
Jump_000_34dd:
    ld a, $1c
    call Call_000_3e9d
    ld a, b
    and a
    ret


Call_000_34e5:
    ld [$d0e3], a
    ld b, $01
    ld hl, $7fca
    jp Jump_000_3620


Call_000_34f0:
Jump_000_34f0:
    call Call_000_34f8
    ld c, $06
    jp Jump_000_3781


Call_000_34f8:
    ld a, $09
    ldh [$8b], a

Call_000_34fc:
    call Call_000_3546
    ldh a, [$8d]
    ld [hl], a
    ret


Call_000_3503:
    ld de, $fff9
    add hl, de
    ld [hl], a
    ret


Call_000_3509:
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a

Jump_000_3511:
    xor a
    ld [$cd3d], a

jr_000_3515:
    ld a, [hl+]
    cp $ff
    jr z, jr_000_352c

    push hl
    ld hl, $cd3d
    inc [hl]
    pop hl
    cp b
    jr z, jr_000_3526

    inc hl
    jr jr_000_3515

jr_000_3526:
    ld a, [hl+]
    cp c
    jr nz, jr_000_3515

    scf
    ret


jr_000_352c:
    and a
    ret


Call_000_352e:
    push hl
    ld hl, $c204
    ldh a, [$8c]
    swap a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl+]
    sub $04
    ld b, a
    ld a, [hl]
    sub $04
    ld c, a
    pop hl
    jp Jump_000_3511


Call_000_3546:
    ld h, $c1
    jr jr_000_354c

Call_000_354a:
    ld h, $c2

jr_000_354c:
    ldh a, [$8b]
    ld b, a
    ldh a, [$8c]
    swap a
    add b

Call_000_3554:
    ld l, a
    ret


Call_000_3556:
    xor a
    ld [$ccd2], a

jr_000_355a:
    ld a, [de]

Jump_000_355b:
    cp $ff
    jr z, jr_000_3575

    ldh [$8b], a
    inc de
    ld a, [de]
    ld b, $00
    ld c, a
    ld a, [$ccd2]
    add c
    ld [$ccd2], a
    ldh a, [$8b]
    call Call_000_372a
    inc de
    jr jr_000_355a

jr_000_3575:
    ld a, $ff
    ld [hl], a
    ld a, [$ccd2]
    inc a
    ret


    push hl
    call Call_000_3598
    ld [hl], $fe
    call Call_000_35a2
    ldh a, [$8d]
    ld [hl], a
    pop hl
    ret


Call_000_358b:
Jump_000_358b:
    push hl
    call Call_000_3598
    ld [hl], $ff
    call Call_000_35a2
    ld [hl], $ff
    pop hl
    ret


Call_000_3598:
    ld h, $c2
    ldh a, [$8c]
    swap a
    add $06
    ld l, a
    ret


Call_000_35a2:
    push de

Call_000_35a3:
    ld hl, $d463
    ldh a, [$8c]
    dec a
    add a
    ld d, $00
    ld e, a
    add hl, de
    pop de
    ret


Call_000_35b0:
    call Call_000_35e8
    ld a, [$d0f0]
    and a
    jr nz, jr_000_35de

    ld a, $0e
    call Call_000_3606
    ld a, [$d018]
    dec a
    ld hl, $5c31
    ld bc, $0005
    call Call_000_3ad1
    ld de, $d01a
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    ld de, $d025
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]

Jump_000_35da:
    ld [de], a
    jp Jump_000_3617


jr_000_35de:
    ld hl, $d01a
    ld de, $5941
    ld [hl], e
    inc hl
    ld [hl], d
    ret


Call_000_35e8:
    ld b, $04
    ld hl, $7fb3
    jp Jump_000_3620


Call_000_35f0:
    ld de, $d2cb
    ld hl, $ff9f
    ld c, $03
    jp Jump_000_3ad8


Call_000_35fb:
Jump_000_35fb:
    ld de, $d523
    ld hl, $ffa0
    ld c, $02
    jp Jump_000_3ad8


Call_000_3606:
    ld [$cf04], a
    ldh a, [$b8]
    ld [$cf03], a
    ld a, [$cf04]
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3617:
Jump_000_3617:
    ld a, [$cf03]
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3620:
Jump_000_3620:
    ldh a, [$b8]
    push af
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ld bc, $362e
    push bc
    jp hl


    pop bc
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3636:
    call Call_000_3761
    call Call_000_3649
    jr jr_000_3672

    ld a, $14
    ld [$d0ea], a
    call Call_000_3649
    jp Jump_000_3130


Call_000_3649:
    xor a
    ld [$d0f1], a
    ld hl, $c43a
    ld bc, $080f
    ret


Call_000_3654:
    call Call_000_3761
    ld a, $06
    ld [$d0f1], a
    ld hl, $c425
    ld bc, $080e
    jr jr_000_3672

    call Call_000_3761
    ld a, $03
    ld [$d0f1], a
    ld hl, $c438
    ld bc, $080d

jr_000_3672:
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    jp Jump_000_376d


Call_000_367d:
    sub b
    ret nc

    cpl
    add $01
    scf
    ret


Call_000_3684:
Jump_000_3684:
    call Call_000_358b

Jump_000_3687:
    push hl
    push bc
    call Call_000_3598
    xor a
    ld [hl], a
    ld hl, $cc5b
    ld c, $00

jr_000_3693:
    ld a, [de]
    ld [hl+], a
    inc de
    inc c
    cp $ff
    jr nz, jr_000_3693

    ld a, c
    ld [$cf0a], a
    pop bc
    ld hl, $d6af
    set 0, [hl]
    pop hl
    xor a
    ld [$cd3b], a
    ld [$ccd3], a
    dec a
    ld [$cd66], a
    ld [$cd3a], a
    ret


Call_000_36b5:
    push hl
    ld hl, $ffe7
    xor a
    ld [hl-], a
    ld a, [hl-]
    and a
    jr z, jr_000_36c8

    ld a, [hl+]

jr_000_36c0:
    sub [hl]
    jr c, jr_000_36c8

    inc hl

Call_000_36c4:
    inc [hl]
    dec hl
    jr jr_000_36c0

jr_000_36c8:
    pop hl
    ret


Call_000_36ca:
    ldh a, [rLCDC]
    bit 7, a
    jr nz, jr_000_36de

    ld hl, $4b19
    ld de, $8800
    ld bc, $0400
    ld a, $04
    jp Jump_000_02c0


jr_000_36de:
    ld de, $4b19
    ld hl, $8800
    ld bc, $0480
    jp Jump_000_031b


Call_000_36ea:
Jump_000_36ea:
    ldh a, [rLCDC]
    bit 7, a
    jr nz, jr_000_36fe

    ld hl, $52f1
    ld de, $9600
    ld bc, $0200

Call_000_36f9:
    ld a, $04
    jp Jump_000_028c


jr_000_36fe:
    ld de, $52f1
    ld hl, $9600
    ld bc, $0420
    jp Jump_000_02dd


Call_000_370a:
    ldh a, [rLCDC]
    bit 7, a
    jr nz, jr_000_371e

    ld hl, $4f39
    ld de, $9620
    ld bc, $01e0
    ld a, $04
    jp Jump_000_028c


jr_000_371e:
    ld de, $4f39
    ld hl, $9620
    ld bc, $041e
    jp Jump_000_02dd


Call_000_372a:
Jump_000_372a:
    push de
    ld d, a

jr_000_372c:
    ld a, d
    ld [hl+], a
    dec bc
    ld a, b
    or c
    jr nz, jr_000_372c

    pop de
    ret


Call_000_3735:
    ld hl, $d088
    ld [hl], e
    inc hl
    ld [hl], d
    jp Jump_000_0fce


Call_000_373e:
    ld hl, $c3a0
    ld de, $cd7c
    ld bc, $0168
    jp Jump_000_01bb


Call_000_374a:
Jump_000_374a:
    call Call_000_3752
    ld a, $01
    ldh [$ba], a
    ret


Call_000_3752:
    xor a
    ldh [$ba], a
    ld hl, $cd7c
    ld de, $c3a0
    ld bc, $0168
    jp Jump_000_01bb


Call_000_3761:
Jump_000_3761:
    ld hl, $c3a0
    ld de, $c508
    ld bc, $0168
    jp Jump_000_01bb


Call_000_376d:
Jump_000_376d:
    xor a
    ldh [$ba], a
    ld hl, $c508
    ld de, $c3a0
    ld bc, $0168
    call Call_000_01bb
    ld a, $01
    ldh [$ba], a
    ret


Call_000_3781:
Jump_000_3781:
jr_000_3781:
    call Call_000_0b31
    dec c
    jr nz, jr_000_3781

    ret


Call_000_3788:
Jump_000_3788:
    push af
    call Call_000_3790

Call_000_378c:
    pop af
    jp Jump_000_0e45


Call_000_3790:
Jump_000_3790:
    ld a, [$d060]
    and $80
    ret nz

    push hl

jr_000_3797:
    ld hl, $c02a
    xor a
    or [hl]
    inc hl
    or [hl]
    inc hl
    inc hl
    or [hl]
    jr nz, jr_000_3797

    pop hl
    ret


    ld l, b
    ld d, b
    nop
    ld b, b
    push af
    ld b, l
    ccf
    ld b, e
    inc sp
    jp nc, $d92b

    inc e
    ld e, l

Call_000_37b3:
    ld a, [$d092]
    ld [$d0e3], a
    cp $c4
    jp nc, Jump_000_1b01

    ldh a, [$b8]
    push af
    push hl
    push bc
    push de
    ld a, [$d093]
    dec a
    jr nz, jr_000_37d5

    call Call_000_1aab
    ld hl, $0006
    add hl, de
    ld e, l
    ld d, h
    jr jr_000_3815

jr_000_37d5:
    ld a, [$d094]
    ldh [$b8], a
    ld [$2000], a
    ld a, [$d093]
    dec a
    add a
    ld d, $00
    ld e, a
    jr nc, jr_000_37e8

    inc d

jr_000_37e8:
    ld hl, $37a5
    add hl, de
    ld a, [hl+]
    ldh [$96], a
    ld a, [hl]
    ldh [$95], a
    ldh a, [$95]
    ld h, a
    ldh a, [$96]
    ld l, a
    call Call_000_00c6
    ld b, a
    ld c, $00

Jump_000_37fe:
jr_000_37fe:
    ld d, h
    ld e, l

jr_000_3800:
    ld a, [hl+]
    cp $50
    jr nz, jr_000_3800

    inc c
    ld a, b
    cp c
    jr nz, jr_000_37fe

    ld h, d
    ld l, e

Call_000_380c:
    ld de, $cd68
    ld bc, $0014
    call Call_000_01bb

Jump_000_3815:
jr_000_3815:
    ld a, e
    ld [$cf74], a

Jump_000_3819:
    ld a, d
    ld [$cf75], a
    pop de
    pop bc
    pop hl
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3827:
    ldh a, [$b8]
    push af
    ld a, [$cf7b]
    cp $01
    ld a, $01
    jr nz, jr_000_3835

    ld a, $0f

jr_000_3835:
    ldh [$b8], a

Call_000_3837:
    ld [$2000], a
    ld hl, $cf76
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$cf78]
    cp $c4
    jr nc, jr_000_385a

    ld bc, $0003

jr_000_384a:
    add hl, bc
    dec a
    jr nz, jr_000_384a

    dec hl
    ld a, [hl-]
    ldh [$8d], a
    ld a, [hl-]

Call_000_3853:
    ldh [$8c], a
    ld a, [hl]
    ldh [$8b], a
    jr jr_000_3864

jr_000_385a:
    ld a, $1e
    ldh [$b8], a
    ld [$2000], a
    call $7fb2

jr_000_3864:
    ld de, $ff8b
    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_386e:
Jump_000_386e:
    ld hl, $cf45

Call_000_3871:
jr_000_3871:
    ld a, [de]
    inc de
    ld [hl+], a
    cp $50
    jr nz, jr_000_3871

    ret


Call_000_3879:
    call Call_000_0153
    ld a, [$ffb7]
    and a
    ldh a, [$b3]
    jr z, jr_000_3886

Jump_000_3884:
    ldh a, [$b4]

jr_000_3886:
    ldh [$b5], a
    ldh a, [$b3]
    and a
    jr z, jr_000_3892

    ld a, $1e
    ldh [$d5], a
    ret


jr_000_3892:
    ldh a, [$d5]

Call_000_3894:
    and a
    jr z, jr_000_389b

    xor a
    ldh [$b5], a
    ret


jr_000_389b:
    ldh a, [$b4]
    and $03
    jr z, jr_000_38a9

    ldh a, [$b6]
    and a

Call_000_38a4:
    jr nz, jr_000_38a9

    xor a
    ldh [$b5], a

jr_000_38a9:
    ld a, $05
    ldh [$d5], a
    ret


Call_000_38ae:
Jump_000_38ae:
    ldh a, [$8b]
    push af
    ldh a, [$8c]
    push af
    xor a
    ldh [$8b], a
    ld a, $06
    ldh [$8c], a

jr_000_38bb:
    push hl
    ld a, [$d078]
    and a
    jr z, jr_000_38c5

    call $5b8a

jr_000_38c5:
    ld hl, $c4f2

Call_000_38c8:
    call Call_000_3c34
    pop hl
    call Call_000_3879
    ld a, $2d
    call Call_000_3e9d
    ldh a, [$b5]
    and $03
    jr z, jr_000_38bb

    pop af
    ldh [$8c], a
    pop af
    ldh [$8b], a
    ret


Call_000_38e1:
    ld a, [$d0f0]
    cp $04
    jr z, jr_000_38f0

Call_000_38e8:
    call Call_000_38ae
    ld a, $90
    jp Jump_000_0e45


jr_000_38f0:
    ld c, $41
    jp Jump_000_3781


Call_000_38f5:
Jump_000_38f5:
    push hl
    push bc
    ld hl, $7e73
    ld b, $0d

Call_000_38fc:
    call Call_000_3620
    pop bc
    pop hl
    ret


Call_000_3902:
    push hl
    push de
    push bc

Call_000_3905:
    ld a, [$ffb8]
    push af
    ld a, $0d
    ldh [$b8], a
    ld [$2000], a

Call_000_3910:
    call $7ed7
    pop af
    ldh [$b8], a
    ld [$2000], a

Jump_000_3919:
    pop bc
    pop de
    pop hl
    ret


Call_000_391d:
Jump_000_391d:
    ld a, [$d6af]
    bit 6, a
    ret nz

    ld a, [$d2d7]
    bit 1, a
    ret z

    push hl
    push de
    push bc
    ld a, [$d2d7]
    bit 0, a
    jr z, jr_000_393c

    ld a, [$d2d4]
    and $0f
    ldh [$d5], a
    jr jr_000_3940

jr_000_393c:
    ld a, $01
    ldh [$d5], a

jr_000_3940:
    call Call_000_0153
    ldh a, [$b4]
    bit 0, a
    jr z, jr_000_394b

    jr jr_000_394f

jr_000_394b:
    bit 1, a
    jr z, jr_000_3954

jr_000_394f:
    call Call_000_0b31
    jr jr_000_3959

jr_000_3954:
    ldh a, [$d5]
    and a
    jr nz, jr_000_3940

jr_000_3959:
    pop bc
    pop de
    pop hl
    ret


Call_000_395d:
Jump_000_395d:
jr_000_395d:
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, h
    cp b
    jr nz, jr_000_395d

    ld a, l
    cp c
    jr nz, jr_000_395d

    ret


Call_000_3969:
    ld hl, $7f1a
    ld b, $01
    jp Jump_000_3620


Call_000_3971:
    push hl
    push de
    push bc
    ld b, $03
    ld hl, $7617
    call Call_000_3620
    pop bc
    pop de
    pop hl
    ret


Call_000_3980:
Jump_000_3980:
    ld c, $00

jr_000_3982:
    inc c
    call Call_000_3994

Call_000_3986:
    ldh a, [$97]
    ld [de], a
    inc de
    ldh a, [$98]
    ld [de], a
    inc de
    ld a, c
    cp $05
    jr nz, jr_000_3982

    ret


Call_000_3994:
    push hl
    push de
    push bc
    ld a, b
    ld d, a
    push hl
    ld hl, $d095
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld e, a
    pop hl
    push hl
    sla c

Call_000_39a6:
    ld a, d
    and a
    jr z, jr_000_39c9

    add hl, bc

jr_000_39ab:
    xor a
    ldh [$96], a
    ldh [$97], a
    inc b
    ld a, b
    cp $ff
    jr z, jr_000_39c9

Call_000_39b6:
    ldh [$98], a

Call_000_39b8:
    ldh [$99], a
    call Call_000_38f5
    ld a, [hl-]
    ld d, a
    ldh a, [$98]
    sub d
    ld a, [hl+]
    ld d, a
    ldh a, [$97]
    sbc d
    jr c, jr_000_39ab

jr_000_39c9:
    srl c
    pop hl
    push bc
    ld bc, $000b
    add hl, bc
    pop bc
    ld a, c
    cp $02
    jr z, jr_000_3a09

    cp $03
    jr z, jr_000_3a10

    cp $04
    jr z, jr_000_3a15

    cp $05
    jr z, jr_000_3a1d

Jump_000_39e3:
    push bc
    ld a, [hl]
    swap a
    and $01
    sla a
    sla a
    sla a
    ld b, a
    ld a, [hl+]
    and $01
    sla a
    sla a
    add b
    ld b, a
    ld a, [hl]
    swap a
    and $01
    sla a
    add b
    ld b, a
    ld a, [hl]
    and $01
    add b
    pop bc
    jr jr_000_3a21

jr_000_3a09:
    ld a, [hl]
    swap a
    and $0f
    jr jr_000_3a21

jr_000_3a10:
    ld a, [hl]
    and $0f
    jr jr_000_3a21

jr_000_3a15:
    inc hl

Jump_000_3a16:
    ld a, [hl]
    swap a

Jump_000_3a19:
    and $0f
    jr jr_000_3a21

jr_000_3a1d:
    inc hl
    ld a, [hl]
    and $0f

jr_000_3a21:
    ld d, $00

Jump_000_3a23:
    add e
    ld e, a
    jr nc, jr_000_3a28

    inc d

jr_000_3a28:
    sla e
    rl d
    srl b
    srl b
    ld a, b
    add e
    jr nc, jr_000_3a35

    inc d

jr_000_3a35:
    ldh [$98], a
    ld a, d
    ldh [$97], a
    xor a
    ldh [$96], a
    ld a, [$d0ec]
    ldh [$99], a
    call Call_000_38f5
    ldh a, [$96]
    ldh [$95], a
    ldh a, [$97]
    ldh [$96], a
    ldh a, [$98]

Jump_000_3a4f:
    ldh [$97], a
    ld a, $64
    ldh [$99], a
    ld a, $03
    ld b, a
    call Call_000_3902
    ld a, c
    cp $01
    ld a, $05
    jr nz, jr_000_3a74

    ld a, [$d0ec]
    ld b, a
    ldh a, [$98]
    add b
    ldh [$98], a
    jr nc, jr_000_3a72

    ldh a, [$97]
    inc a
    ldh [$97], a

jr_000_3a72:
    ld a, $0a

jr_000_3a74:
    ld b, a
    ldh a, [$98]
    add b
    ldh [$98], a
    jr nc, jr_000_3a81

    ldh a, [$97]
    inc a

Call_000_3a7f:
Jump_000_3a7f:
    ldh [$97], a

jr_000_3a81:
    ldh a, [$97]
    cp $04

Call_000_3a85:
    jr nc, jr_000_3a91

    cp $03
    jr c, jr_000_3a99

    ldh a, [$98]
    cp $e8

Jump_000_3a8f:
    jr c, jr_000_3a99

jr_000_3a91:
    ld a, $03
    ldh [$97], a

Call_000_3a95:
    ld a, $e7
    ldh [$98], a

jr_000_3a99:
    pop bc
    pop de
    pop hl
    ret


Call_000_3a9d:
    ldh a, [$b8]
    push af
    ld a, $03
    ldh [$b8], a

Jump_000_3aa4:
    ld [$2000], a
    call $77d3

Jump_000_3aaa:
    pop bc
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3ab2:
    ldh a, [$b8]

Jump_000_3ab4:
    push af

Jump_000_3ab5:
    ld a, $03
    ldh [$b8], a

Jump_000_3ab9:
    ld [$2000], a
    call $7854
    pop bc
    ld a, b
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3ac7:
Jump_000_3ac7:
    and a
    ret z

    ld bc, $0006

jr_000_3acc:
    add hl, bc
    dec a
    jr nz, jr_000_3acc

    ret


Call_000_3ad1:
    and a
    ret z

jr_000_3ad3:
    add hl, bc
    dec a
    jr nz, jr_000_3ad3

    ret


Call_000_3ad8:
Jump_000_3ad8:
jr_000_3ad8:
    ld a, [de]
    cp [hl]

Jump_000_3ada:
    ret nz

    inc de
    inc hl
    dec c

Jump_000_3ade:
    jr nz, jr_000_3ad8

    ret


Call_000_3ae1:
Jump_000_3ae1:
    ld h, $c3
    swap a
    ld l, a
    call Call_000_3afd
    push bc
    ld a, $08

Jump_000_3aec:
    add c
    ld c, a
    call Call_000_3afd
    pop bc
    ld a, $08
    add b
    ld b, a
    call Call_000_3afd
    ld a, $08
    add c
    ld c, a

Call_000_3afd:
Jump_000_3afd:
    ld [hl], b
    inc hl
    ld [hl], c
    inc hl
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl+], a
    ret


Call_000_3b08:
Jump_000_3b08:
    xor a

Jump_000_3b09:
    ld [$d078], a

Call_000_3b0c:
    ldh a, [$8b]

Jump_000_3b0e:
    push af
    ldh a, [$8c]
    push af
    xor a
    ldh [$8b], a
    ld a, $06

Jump_000_3b17:
    ldh [$8c], a

Jump_000_3b19:
    xor a
    ld [$d068], a
    call Call_000_3bc6
    call Call_000_3e07

jr_000_3b23:
    push hl
    ld a, [$d078]
    and a
    jr z, jr_000_3b32

    ld b, $1c
    ld hl, $5bc3
    call Call_000_3620

jr_000_3b32:
    pop hl
    call Call_000_3879
    ldh a, [$b5]
    and a
    jr nz, jr_000_3b56

    push hl

Call_000_3b3c:
    ld hl, $c48e
    call Call_000_3c34
    pop hl
    ld a, [$cc34]
    dec a
    jr z, jr_000_3b4b

    jr jr_000_3b23

jr_000_3b4b:
    pop af
    ldh [$8c], a
    pop af
    ldh [$8b], a
    xor a
    ld [$cc4a], a
    ret


jr_000_3b56:
    xor a
    ld [$cc4b], a
    ldh a, [$b5]
    ld b, a
    bit 6, a
    jr z, jr_000_3b7b

    ld a, [$cc26]
    and a
    jr z, jr_000_3b6d

    dec a
    ld [$cc26], a
    jr jr_000_3b96

jr_000_3b6d:
    ld a, [$cc4a]
    and a
    jr z, jr_000_3bbe

    ld a, [$cc28]
    ld [$cc26], a
    jr jr_000_3b96

jr_000_3b7b:
    bit 7, a
    jr z, jr_000_3b96

    ld a, [$cc26]
    inc a
    ld c, a
    ld a, [$cc28]
    cp c
    jr nc, jr_000_3b92

    ld a, [$cc4a]
    and a
    jr z, jr_000_3bbe

    ld c, $00

jr_000_3b92:
    ld a, c
    ld [$cc26], a

jr_000_3b96:
    ld a, [$cc29]
    and b
    jp z, Jump_000_3b19

jr_000_3b9d:
    ldh a, [$b5]
    and $03
    jr z, jr_000_3bb1

    push hl
    ld hl, $cd5b
    bit 5, [hl]
    pop hl
    jr nz, jr_000_3bb1

    ld a, $90
    call Call_000_0e45

jr_000_3bb1:
    pop af
    ldh [$8c], a
    pop af
    ldh [$8b], a

Jump_000_3bb7:
    xor a
    ld [$cc4a], a
    ldh a, [$b5]
    ret


jr_000_3bbe:
    ld a, [$cc37]
    and a
    jr z, jr_000_3b96

    jr jr_000_3b9d

Call_000_3bc6:
    ld a, [$cc24]
    and a
    jr z, jr_000_3bd6

    ld hl, $c3a0
    ld bc, $0014

jr_000_3bd2:
    add hl, bc
    dec a
    jr nz, jr_000_3bd2

jr_000_3bd6:
    ld a, [$cc25]
    ld b, $00
    ld c, a
    add hl, bc
    push hl
    ld a, [$cc2a]
    and a
    jr z, jr_000_3beb

    ld bc, $0028

jr_000_3be7:
    add hl, bc
    dec a
    jr nz, jr_000_3be7

jr_000_3beb:
    ld a, [hl]
    cp $ed
    jr nz, jr_000_3bf4

    ld a, [$cc27]
    ld [hl], a

jr_000_3bf4:
    pop hl
    ld a, [$cc26]
    and a
    jr z, jr_000_3c02

    ld bc, $0028

jr_000_3bfe:
    add hl, bc
    dec a

Call_000_3c00:
    jr nz, jr_000_3bfe

jr_000_3c02:
    ld a, [hl]

Jump_000_3c03:
    cp $ed
    jr z, jr_000_3c0a

    ld [$cc27], a

Call_000_3c0a:
jr_000_3c0a:
    ld a, $ed
    ld [hl], a
    ld a, l
    ld [$cc30], a
    ld a, h
    ld [$cc31], a
    ld a, [$cc26]
    ld [$cc2a], a
    ret


Call_000_3c1c:
    ld b, a
    ld a, [$cc30]
    ld l, a
    ld a, [$cc31]
    ld h, a
    ld [hl], $ec
    ld a, b
    ret


Call_000_3c29:
Jump_000_3c29:
    ld a, [$cc30]
    ld l, a

Call_000_3c2d:
    ld a, [$cc31]
    ld h, a
    ld [hl], $7f
    ret


Call_000_3c34:
    ld a, [hl]
    ld b, a
    ld a, $ee
    cp b
    jr nz, jr_000_3c53

    ldh a, [$8b]
    dec a
    ldh [$8b], a
    ret nz

    ldh a, [$8c]
    dec a
    ldh [$8c], a
    ret nz

    ld a, $7f
    ld [hl], a
    ld a, $ff
    ldh [$8b], a
    ld a, $06
    ldh [$8c], a
    ret


jr_000_3c53:
    ldh a, [$8b]

Jump_000_3c55:
    and a
    ret z

    dec a
    ldh [$8b], a
    ret nz

    dec a
    ldh [$8b], a
    ldh a, [$8c]
    dec a
    ldh [$8c], a
    ret nz

    ld a, $06
    ldh [$8c], a
    ld a, $ee

Jump_000_3c6a:
    ld [hl], a
    ret


Call_000_3c6c:
Jump_000_3c6c:
    xor a
    jr jr_000_3c71

Jump_000_3c6f:
    ld a, $01

jr_000_3c71:
    ld [$cf07], a
    xor a
    ld [$cc3c], a
    ret


Call_000_3c79:
Jump_000_3c79:
    push hl
    ld a, $01
    ld [$d0ea], a

Call_000_3c7f:
Jump_000_3c7f:
    call Call_000_3130
    call Call_000_0ebd
    call Call_000_3e07
    pop hl

Call_000_3c89:
    ld bc, $c4b9
    jp Jump_000_095e


Call_000_3c8f:
Jump_000_3c8f:
    push bc
    xor a
    ldh [$95], a
    ldh [$96], a
    ldh [$97], a
    ld a, b
    and $0f

Call_000_3c9a:
    cp $01
    jr z, jr_000_3cb8

Call_000_3c9e:
    cp $02
    jr z, jr_000_3caf

    ld a, [de]
    ldh [$96], a
    inc de
    ld a, [de]

Call_000_3ca7:
    ldh [$97], a
    inc de

Jump_000_3caa:
    ld a, [de]
    ldh [$98], a
    jr jr_000_3cbb

jr_000_3caf:
    ld a, [de]
    ldh [$97], a

Jump_000_3cb2:
    inc de
    ld a, [de]
    ldh [$98], a
    jr jr_000_3cbb

Jump_000_3cb8:
jr_000_3cb8:
    ld a, [de]
    ldh [$98], a

jr_000_3cbb:
    push de
    ld d, b
    ld a, c
    ld b, a
    xor a
    ld c, a
    ld a, b
    cp $02
    jr z, jr_000_3d2c

    cp $03
    jr z, jr_000_3d1c

    cp $04
    jr z, jr_000_3d0b

    cp $05
    jr z, jr_000_3cfa

    cp $06

Jump_000_3cd4:
    jr z, jr_000_3ce8

    ld a, $0f
    ldh [$99], a
    ld a, $42
    ldh [$9a], a

Jump_000_3cde:
    ld a, $40
    ldh [$9b], a
    call Call_000_3d55
    call Call_000_3db9

jr_000_3ce8:
    ld a, $01
    ldh [$99], a
    ld a, $86
    ldh [$9a], a
    ld a, $a0
    ldh [$9b], a
    call Call_000_3d55
    call Call_000_3db9

jr_000_3cfa:
    xor a
    ldh [$99], a

Call_000_3cfd:
    ld a, $27

Jump_000_3cff:
    ldh [$9a], a
    ld a, $10
    ldh [$9b], a
    call Call_000_3d55

Jump_000_3d08:
    call Call_000_3db9

jr_000_3d0b:
    xor a

Jump_000_3d0c:
    ldh [$99], a

Jump_000_3d0e:
    ld a, $03
    ldh [$9a], a
    ld a, $e8
    ldh [$9b], a
    call Call_000_3d55
    call Call_000_3db9

jr_000_3d1c:
    xor a
    ldh [$99], a
    xor a
    ldh [$9a], a
    ld a, $64
    ldh [$9b], a
    call Call_000_3d55
    call Call_000_3db9

jr_000_3d2c:
    ld c, $00
    ldh a, [$98]

jr_000_3d30:
    cp $0a
    jr c, jr_000_3d39

    sub $0a
    inc c
    jr jr_000_3d30

jr_000_3d39:
    ld b, a
    ldh a, [$95]
    or c
    ldh [$95], a
    jr nz, jr_000_3d46

    call Call_000_3db3
    jr jr_000_3d4a

jr_000_3d46:
    ld a, $f6
    add c
    ld [hl], a

jr_000_3d4a:
    call Call_000_3db9
    ld a, $f6
    add b
    ld [hl+], a
    pop de
    dec de
    pop bc
    ret


Call_000_3d55:
    ld c, $00

jr_000_3d57:
    ldh a, [$99]
    ld b, a
    ldh a, [$96]
    ldh [$9c], a
    cp b
    jr c, jr_000_3da7

    sub b
    ldh [$96], a
    ldh a, [$9a]
    ld b, a
    ldh a, [$97]
    ldh [$9d], a
    cp b
    jr nc, jr_000_3d79

    ldh a, [$96]
    or $00
    jr z, jr_000_3da3

    dec a
    ldh [$96], a
    ldh a, [$97]

jr_000_3d79:
    sub b
    ldh [$97], a
    ldh a, [$9b]
    ld b, a
    ldh a, [$98]
    ldh [$9e], a
    cp b
    jr nc, jr_000_3d99

    ldh a, [$97]
    and a
    jr nz, jr_000_3d94

    ldh a, [$96]
    and a
    jr z, jr_000_3d9f

    dec a
    ldh [$96], a
    xor a

jr_000_3d94:
    dec a
    ldh [$97], a
    ldh a, [$98]

Jump_000_3d99:
jr_000_3d99:
    sub b
    ldh [$98], a
    inc c
    jr jr_000_3d57

jr_000_3d9f:
    ldh a, [$9d]
    ldh [$97], a

jr_000_3da3:
    ldh a, [$9c]
    ldh [$96], a

jr_000_3da7:
    ldh a, [$95]
    or c

Jump_000_3daa:
    jr z, jr_000_3db3

    ld a, $f6
    add c
    ld [hl], a
    ldh [$95], a
    ret


Call_000_3db3:
jr_000_3db3:
    bit 7, d
    ret z

    ld [hl], $f6

Call_000_3db8:
    ret


Call_000_3db9:
    bit 7, d
    jr nz, jr_000_3dc5

    bit 6, d
    jr z, jr_000_3dc5

    ldh a, [$95]
    and a
    ret z

jr_000_3dc5:
    inc hl
    ret


Call_000_3dc7:
Jump_000_3dc7:
    push hl
    push de
    push bc
    add a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $3dd7
    push de
    jp hl


    pop bc
    pop de
    pop hl
    ret


Call_000_3ddb:
Jump_000_3ddb:
    ld b, $00

Call_000_3ddd:
    ld c, a

jr_000_3dde:
    ld a, [hl]
    cp $ff
    jr z, jr_000_3dea

    cp c
    jr z, jr_000_3dec

    inc b
    add hl, de
    jr jr_000_3dde

jr_000_3dea:
    and a
    ret


jr_000_3dec:
    scf
    ret


Call_000_3dee:
    call Call_000_0188
    ld a, $01
    ld [$cfb2], a
    call Call_000_3e38
    call Call_000_374a
    call Call_000_36ea
    call Call_000_3e1d
    jr jr_000_3e07

Call_000_3e04:
    call Call_000_3e15

Call_000_3e07:
Jump_000_3e07:
jr_000_3e07:
    ld c, $03
    jp Jump_000_3781


Call_000_3e0c:
Jump_000_3e0c:
    ld a, $e4
    ldh [rBGP], a
    ld a, $d0
    ldh [rOBP0], a
    ret


Call_000_3e15:
Jump_000_3e15:
    xor a
    ldh [rBGP], a
    ldh [rOBP0], a
    ldh [rOBP1], a
    ret


Call_000_3e1d:
Jump_000_3e1d:
    ld b, $ff

Call_000_3e1f:
Jump_000_3e1f:
    ld a, [$cf15]
    and a
    ret z

    ld a, $45
    jp Jump_000_3e9d


Call_000_3e29:
    ld a, e
    cp $1b
    ld d, $00
    jr nc, jr_000_3e36

Call_000_3e30:
    cp $0a
    inc d
    jr nc, jr_000_3e36

    inc d

jr_000_3e36:
    ld [hl], d
    ret


Call_000_3e38:
    ld hl, $cfab
    ld a, [hl]
    push af
    res 0, [hl]
    push hl
    xor a
    ld [$d327], a
    call Call_000_0167
    ld b, $05
    ld hl, $7840
    call Call_000_3620

Jump_000_3e4f:
    call Call_000_0181
    pop hl
    pop af
    ld [hl], a

Jump_000_3e55:
    call Call_000_23ae
    call Call_000_36ca
    jp Jump_000_0ebd


Call_000_3e5e:
    ld a, b
    ld [$d0e3], a
    ld [$cf78], a
    ld a, c
    ld [$cf7d], a
    ld hl, $d2a1
    call Call_000_16e0
    ret nc

    call Call_000_1add
    call Call_000_386e
    scf
    ret


Call_000_3e78:
    ld a, b
    ld [$cf78], a
    ld a, c
    ld [$d0ec], a
    xor a
    ld [$cc49], a
    ld b, $13
    ld hl, $7da1
    jp Jump_000_3620


Call_000_3e8c:
Jump_000_3e8c:
    push hl
    push de
    push bc
    ld b, $04
    ld hl, $7fea
    call Call_000_3620
    ldh a, [$d3]
    pop bc
    pop de
    pop hl
    ret


Call_000_3e9d:
Jump_000_3e9d:
    ld [$cc4e], a
    ldh a, [$b8]
    ld [$cf0d], a
    push af

Jump_000_3ea6:
    ld a, $13

Jump_000_3ea8:
    ldh [$b8], a
    ld [$2000], a
    call $7ea5
    ld a, [$d094]
    ldh [$b8], a
    ld [$2000], a
    ld de, $3ebd
    push de
    jp hl


    pop af
    ldh [$b8], a
    ld [$2000], a
    ret


Call_000_3ec4:
    ld a, [$cc4f]
    ld h, a
    ld a, [$cc50]
    ld l, a
    ld a, [$cc51]
    ld d, a
    ld a, [$cc52]
    ld e, a
    ld a, [$cc53]
    ld b, a
    ld a, [$cc54]
    ld c, a
    ret


Call_000_3edd:
    ld b, $07
    ld hl, $7d15
    jp Jump_000_3620


Call_000_3ee5:
    ldh a, [$b8]
    push af
    ldh a, [$b4]

Call_000_3eea:
    bit 0, a
    jr z, jr_000_3f1a

    ld a, $11
    ld [$2000], a
    ldh [$b8], a
    call $78c5
    ldh a, [$ee]
    and a

Jump_000_3efb:
    jr nz, jr_000_3f0d

    ld a, [$cd3e]
    ld [$2000], a
    ldh [$b8], a
    ld de, $3f0a
    push de
    jp hl


    xor a
    jr jr_000_3f1c

jr_000_3f0d:
    ld b, $03
    ld hl, $7e8a
    call Call_000_3620
    ldh a, [$db]
    and a
    jr z, jr_000_3f1c

jr_000_3f1a:
    ld a, $ff

jr_000_3f1c:
    ldh [$eb], a
    pop af
    ld [$2000], a
    ldh [$b8], a
    ret


Call_000_3f25:
Jump_000_3f25:
    ldh [$8c], a
    ld hl, $3f52
    call Call_000_3f3f
    ld hl, $cf0c
    set 0, [hl]
    call Call_000_13f1

Call_000_3f35:
    ld hl, $d2eb
    ldh a, [$ec]
    ld [hl+], a
    ldh a, [$ed]
    ld [hl], a
    ret


Call_000_3f3f:
    ld a, [$d2eb]
    ldh [$ec], a
    ld a, [$d2ec]
    ldh [$ed], a
    ld a, l
    ld [$d2eb], a
    ld a, h
    ld [$d2ec], a
    ret


    ld e, a
    ld a, d

Call_000_3f54:
    ld a, l

Call_000_3f55:
    ld a, d
    dec bc
    ld a, c
    rst $18
    ld a, b
    cp b
    ld a, c
    pop af
    ld a, c
    rrca
    ld a, d
    daa

Jump_000_3f61:
    ld a, a
    ld l, d
    ld a, c
    dec h
    ld a, c
    sub c
    ld a, c
    ld e, e
    ld a, h
    ld [hl], l
    ld a, h
    and c
    ld a, a
    ldh [$7c], a
    ld b, $7d
    dec sp
    ld a, l
    ld h, l
    ld a, l
    ld [hl+], a

Jump_000_3f77:
    ld a, [hl]
    ld [hl], h
    ld a, [hl]
    ld a, d
    ld a, a
    sub a
    ld a, [hl]
    ret c

    ld a, [hl]
    dec d
    ld a, a
    sub b
    ld a, l
    cp h
    ld a, l
    sbc $7d
    db $ed
    ld a, l
    rst $38
    ld a, l
    sbc b
    ld a, a
    rst $08
    ld a, a
    call c, $5d7d
    ld a, e
    ld b, l
    ld b, l
    ld e, [hl]
    ld b, l
    ld c, b
    ld a, [hl]
    adc [hl]
    ld a, [hl]
    rst $08

Jump_000_3f9d:
    ld a, l
    jp c, $ab7f

    ld a, a
    rst $00
    ld a, a
    ld [c], a
    ld a, a
    ld d, d
    ld a, a
    ld l, h
    ld a, a
    ld bc, $197e
    ld a, [hl]
    ld e, b
    ld a, [hl]

Call_000_3fb0:
    ld [hl], h
    ld a, l
    ld sp, hl
    ld a, d
    ld a, [c]
    ld a, a
    ld [c], a

Call_000_3fb7:
    ld a, a
    ld sp, hl
    ld a, c
    add h
    ld a, l
    cp a
    ld a, a
    sbc l
    ld a, a
    xor l
    ld a, a
    and b
    ld a, c
    ld sp, hl
    ld a, [hl]
    or b
    ld a, [hl]
    add hl, bc
    ld a, a
    ld c, [hl]
    ld a, a

Call_000_3fcc:
    adc [hl]
    ld a, a
    sub b
    ld a, a
    ld d, b
    ld a, a
    add d
    ld a, a
    ret


    ld a, a
    and b
    ld a, c
    ld sp, hl
    ld a, [hl]
    or b
    ld a, [hl]
    add hl, bc
    ld a, a
    ld c, [hl]
    ld a, a
    adc [hl]
    ld a, a
    sub b
    ld a, a
    ld d, b

Jump_000_3fe5:
    ld a, a
    add d
    ld a, a
    ret


    ld a, a
    and l
    or a
    ld h, a
    db $e3
    ld [hl], a
    cp e
    db $fd
    ret


    ei
    add l
    rst $20
    ld d, e
    ret


    add c

Call_000_3ff8:
    and e
    rst $00
    ccf
    add l
    inc sp
    ld c, l
    dec d
    nop
