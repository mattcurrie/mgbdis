; ============================================================
; YOSSY NO TAMAGO (Yoshi's Egg) - Constants
; ============================================================

; === Cartridge / ROM banking ===
DEF MBC1_ROM_BANK_REG      EQU $2100
DEF ROM_BANK_MAIN_CODE     EQU $01
DEF ROM_BANK_GRAPHICS_0    EQU $02
DEF ROM_BANK_GRAPHICS_1    EQU $03

; === HRAM Variables ===
DEF OAM_DMA_HRAM      EQU $ff80 ; HRAM上のOAM DMAルーチンコピー先
DEF ANIM_FRAME        EQU $ff8a ; アニメーションフレームカウンタ
DEF STATE_TRANSITION  EQU $ff8b ; 状態遷移フラグ
DEF ANIM_SUBFRAME     EQU $ff8c ; アニメーションサブフレーム
DEF TEXT_FADE         EQU $ff8d ; テキストフェードタイマー
DEF SPRITE_SCAN_SLOT_OFFSET EQU $ff8e ; UpdateSprites中の$C200スロット走査オフセット
DEF SHADOW_OAM_WRITE_OFFSET EQU $ff8f ; UpdateSprites中の$C400書き込みオフセット
DEF SPRITE_BASE_X_TMP EQU $ff90 ; UpdateSprites中のスプライト基準X
DEF SPRITE_BASE_Y_TMP EQU $ff91 ; UpdateSprites中のスプライト基準Y
DEF SPRITE_OBJECT_ATTR_TMP EQU $ff92 ; UpdateSprites中のobject属性OR値
DEF SCREEN_STATE      EQU $ff93 ; 画面状態フラグ
DEF WAVE_UPDATE       EQU $ff9b ; Wave RAMアップデートフラグ
DEF SCX_SHADOW        EQU $ff9c ; SCXシャドウ
DEF JOYPAD_RAW        EQU $ffa0 ; 生入力
DEF JOYPAD_PRESSED    EQU $ffa1 ; 押下検出
DEF JOYPAD_HELD       EQU $ffa2 ; 長押し
DEF GAME_ACTIVE       EQU $ffa5 ; ゲームアクティブフラグ
DEF VRAM_COPY_BLOCKS  EQU $ffae ; VRAM転送ブロック数 (16バイト単位)
DEF VRAM_SRC_LO       EQU $ffaf ; VRAM転送元アドレス(下位)
DEF VRAM_SRC_HI       EQU $ffb0 ; VRAM転送元アドレス(上位)
DEF VRAM_DST_LO       EQU $ffb1 ; VRAM転送先アドレス(下位)
DEF VRAM_DST_HI       EQU $ffb2 ; VRAM転送先アドレス(上位)
DEF VRAM_COPY2_BLOCKS EQU $ffb3 ; 予備/第2VRAM転送ブロック数 (16バイト単位)
DEF VBLANK_BUSY       EQU $ffc4 ; VBlankビジーフラグ
DEF VBLANK_SYNC       EQU $ffc5 ; VBlank同期フラグ
DEF GAME_STATE        EQU $ffc7 ; ゲーム状態 (ステートマシンインデックス)
DEF SERIAL_DONE       EQU $ffc8 ; シリアル転送完了フラグ
DEF SERIAL_TEMP       EQU $ffe0 ; シリアル一時レジスタ

; === Main GAME_STATE values ===
DEF GAME_STATE_TITLE_INIT   EQU $00
DEF GAME_STATE_TITLE_MENU   EQU $01
DEF GAME_STATE_PLAY_SETUP   EQU $02
DEF GAME_STATE_PLAYING      EQU $03
DEF GAME_STATE_ROUND_END    EQU $04
DEF GAME_STATE_PREPLAY_LOOP EQU $05
DEF GAME_STATE_PREPLAY_INIT EQU $06

; === WRAM Variables ===
; Sound engine work RAM. Most channel arrays have 8 entries; channels 0-3 map
; to hardware channels, and 4-7 are secondary/effect tracks that share them.
DEF SOUND_STATUS             EQU $c000
DEF SOUND_COMMAND_ID         EQU $c001
DEF SOUND_PAUSE_FLAG         EQU $c002
DEF SOUND_DEFERRED_ID        EQU $c003
DEF SOUND_OUTPUT_MASK        EQU $c004
DEF SOUND_NR50_BACKUP        EQU $c005
DEF SOUND_CH_SEQUENCE_PTRS   EQU $c006 ; 8 words, current stream pointer
DEF SOUND_CH_RETURN_PTRS     EQU $c016 ; 8 words, $FD return pointer
DEF SOUND_CH_ACTIVE_ID       EQU $c026 ; 8 bytes, active sound command/priority
DEF SOUND_BGM_ACTIVE_ID      EQU $c02a ; 4 bytes, music priority gate
DEF SOUND_CH_FLAGS           EQU $c02e ; 8 bytes
DEF SOUND_CH_GATE_FLAGS      EQU $c036 ; 8 bytes
DEF SOUND_CH_DUTY_LENGTH     EQU $c03e ; 8 bytes, NRx1 base bits
DEF SOUND_CH_DUTY_ROTATE     EQU $c046 ; 8 bytes, rotating duty bits
DEF SOUND_CH_DELAY           EQU $c04e ; 8 bytes, per-channel wait counter
DEF SOUND_CH_VIBRATO_DEPTH   EQU $c056 ; 8 bytes
DEF SOUND_CH_VIBRATO_PHASE   EQU $c05e ; 8 bytes, high nibble reload, low counter
DEF SOUND_CH_FREQ_LO_BASE    EQU $c066 ; 8 bytes
DEF SOUND_CH_DELAY_RELOAD    EQU $c06e ; 8 bytes
DEF SOUND_CH_SLIDE_TICKS     EQU $c076 ; 8 bytes
DEF SOUND_CH_SLIDE_STEP_INT  EQU $c07e ; 8 bytes
DEF SOUND_CH_SLIDE_STEP_FRAC EQU $c086 ; 8 bytes
DEF SOUND_CH_SLIDE_ACCUM     EQU $c08e ; 8 bytes
DEF SOUND_CH_FREQ_HI         EQU $c096 ; 8 bytes
DEF SOUND_CH_FREQ_LO         EQU $c09e ; 8 bytes
DEF SOUND_CH_SLIDE_TARGET_HI EQU $c0a6 ; 8 bytes
DEF SOUND_CH_SLIDE_TARGET_LO EQU $c0ae ; 8 bytes
DEF SOUND_CH_NOTE_LENGTH     EQU $c0b6 ; 8 bytes
DEF SOUND_CH_LOOP_COUNTER    EQU $c0be ; 8 bytes, $FE loop counters
DEF SOUND_CH_LENGTH_SCALE    EQU $c0c6 ; 8 bytes
DEF SOUND_CH_TEMPO_ACCUM     EQU $c0ce ; 8 bytes
DEF SOUND_CH_OCTAVE          EQU $c0d6 ; 8 bytes, pitch table shift count
DEF SOUND_CH_ENVELOPE        EQU $c0de ; 8 bytes, NRx2 value
DEF SOUND_WAVE_PATTERN_MAIN  EQU $c0e6
DEF SOUND_WAVE_PATTERN_ALT   EQU $c0e7
DEF SOUND_MAIN_TEMPO_HI      EQU $c0e8
DEF SOUND_MAIN_TEMPO_LO      EQU $c0e9
DEF SOUND_SFX_TEMPO_HI       EQU $c0ea
DEF SOUND_SFX_TEMPO_LO       EQU $c0eb
DEF SOUND_INDEX_PTR_HI       EQU $c0ec
DEF SOUND_INDEX_PTR_LO       EQU $c0ed

; Sprite/object work areas. `$C200` stores 16-byte logical sprite object slots;
; `UpdateSprites` expands active slots into the `$C400` shadow OAM buffer.
DEF SPRITE_OBJECTS           EQU $c200
DEF SPRITE_OBJECTS_HI        EQU $c2
DEF SPRITE_OBJECT_SLOT_SIZE  EQU $10
DEF SPRITE_OBJECT_COUNT      EQU $10
DEF SPRITE_OBJECT_TYPE       EQU $00
DEF SPRITE_OBJECT_FRAME      EQU $02
DEF SPRITE_OBJECT_BASE_Y     EQU $04
DEF SPRITE_OBJECT_BASE_X     EQU $06
DEF SPRITE_OBJECT_ATTR_MASK  EQU $80
DEF SPRITE_FRAME_ENTRY_SIZE  EQU $04
DEF SPRITE_ATTR_END_BIT      EQU 0
DEF SPRITE_ATTR_INHERIT_BIT  EQU 1
DEF OAM_ENTRY_SIZE           EQU $04
DEF OAM_Y_BIAS               EQU $10
DEF OAM_X_BIAS               EQU $08
DEF OAM_SPRITE_COUNT         EQU $28
DEF OAM_HIDDEN_Y             EQU $a0
DEF SHADOW_OAM               EQU $c400
DEF SHADOW_OAM_HI            EQU $c4
DEF SHADOW_OAM_SIZE          EQU $a0
DEF SHADOW_OAM_HIDE_LIMIT    EQU $98

DEF LCD_REDRAW        EQU $c61c ; LCD再描画フラグ
DEF SCORE_BCD_LOW     EQU $c61d ; スコアBCD下位2桁
DEF SCORE_BCD_MID     EQU $c61e ; スコアBCD中位2桁
DEF SCORE_BCD_HIGH    EQU $c61f ; スコアBCD上位1桁
DEF SCORE_DIGITS      EQU $c621 ; 表示用スコア5桁
DEF BOARD_DATA        EQU $c62a ; 盤面データ開始 (4列×7行)
DEF GAME_TYPE         EQU $c671 ; ゲーム種別 (0=A-TYPE系, 1=B-TYPE系)
DEF PIECE_FALL_POS    EQU $c68f ; ピース落下位置
DEF PIECE_ROTATION    EQU $c691 ; ピース回転状態
DEF MENU_CURSOR       EQU $c6b1 ; メニューカーソル位置
DEF OPTION_GAME_TYPE  EQU $c6b2 ; オプション: ゲーム種別
DEF OPTION_LEVEL      EQU $c6b3 ; オプション: レベル
DEF OPTION_SPEED      EQU $c6b4 ; オプション: 落下速度
DEF OPTION_BGM        EQU $c6b5 ; オプション: BGM
DEF TWO_PLAYER_FLAG   EQU $c6b6 ; 2Pモードフラグ
DEF ACTIVE_LEVEL      EQU $c6b7 ; ゲーム中レベル
DEF ACTIVE_SPEED      EQU $c6b8 ; ゲーム中落下速度
DEF LINK_RECV         EQU $c6b9 ; リンク受信バイト
DEF LINK_SEND         EQU $c6ba ; リンク送信バイト
DEF LINK_ROLE         EQU $c6bb ; リンクケーブルロール (0=なし, 1=マスター, 2=スレーブ)
DEF BGM_PREVIEW_TIMER EQU $c6c1 ; BGMプレビュー用カウントダウン
DEF BGM_PREVIEW_PERIOD EQU $c6c2 ; BGMプレビュー用初期値候補
DEF SPRITE_ANIM_FRAME EQU $c6cf ; スプライトアニメフレーム
DEF SPRITE_ANIM_STATE EQU $c6d0 ; スプライトアニメ状態
DEF BGM_INDEX         EQU $c6e1 ; BGMインデックス
DEF MENU_SELECT       EQU $c6f0 ; メニュー選択インデックス
DEF GAME_MODE_FLAG    EQU $c6f1 ; ゲームモードフラグ
DEF PAUSE_FLAG        EQU $c707 ; ポーズフラグ

; === Sound Commands ===
DEF SND_STOP_ALL      EQU $ff   ; 全サウンド停止
DEF SND_DROP_START    EQU $1b
DEF SND_COMMIT_PIECE  EQU $26
DEF SND_PIECE_LAND    EQU $27
DEF SND_CURSOR_MOVE   EQU $28
DEF SND_ROUND_COMPLETE EQU $2d
DEF SND_PAUSE         EQU $2e
DEF SND_TITLE_BGM     EQU $30
DEF SND_BGM_OPTION0   EQU $34
DEF SND_BGM_PREVIEW0  EQU $38
DEF SND_BGM_OPTION1   EQU $3c
DEF SND_BGM_PREVIEW1  EQU $40
DEF SND_BGM_OPTION2   EQU $44
DEF SND_BGM_PREVIEW2  EQU $48
DEF SND_BGM_OFF       EQU SND_STOP_ALL
DEF SND_LINK_MASTER   EQU $4c
DEF SND_LINK_SLAVE    EQU $50
DEF SND_CONFIRM       EQU $54
