; ============================================================
; YOSSY NO TAMAGO (Yoshi's Egg) - Constants
; ============================================================

; === HRAM Variables ===
DEF ANIM_FRAME        EQU $ff8a ; アニメーションフレームカウンタ
DEF STATE_TRANSITION  EQU $ff8b ; 状態遷移フラグ
DEF ANIM_SUBFRAME     EQU $ff8c ; アニメーションサブフレーム
DEF TEXT_FADE         EQU $ff8d ; テキストフェードタイマー
DEF SCREEN_STATE      EQU $ff93 ; 画面状態フラグ
DEF WAVE_UPDATE       EQU $ff9b ; Wave RAMアップデートフラグ
DEF SCX_SHADOW        EQU $ff9c ; SCXシャドウ
DEF JOYPAD_RAW        EQU $ffa0 ; 生入力
DEF JOYPAD_PRESSED    EQU $ffa1 ; 押下検出
DEF JOYPAD_HELD       EQU $ffa2 ; 長押し
DEF GAME_ACTIVE       EQU $ffa5 ; ゲームアクティブフラグ
DEF VRAM_SRC_LO       EQU $ffae ; VRAM転送元アドレス(下位)
DEF VRAM_SRC_HI       EQU $ffaf ; VRAM転送元アドレス(上位)
DEF VRAM_DST_LO       EQU $ffb0 ; VRAM転送先アドレス(下位)
DEF VRAM_DST_HI       EQU $ffb1 ; VRAM転送先アドレス(上位)
DEF VRAM_LEN_LO       EQU $ffb2 ; VRAM転送長(下位)
DEF VRAM_LEN_HI       EQU $ffb3 ; VRAM転送長(上位)
DEF VBLANK_BUSY       EQU $ffc4 ; VBlankビジーフラグ
DEF VBLANK_SYNC       EQU $ffc5 ; VBlank同期フラグ
DEF GAME_STATE        EQU $ffc7 ; ゲーム状態 (ステートマシンインデックス)
DEF SERIAL_DONE       EQU $ffc8 ; シリアル転送完了フラグ
DEF SERIAL_TEMP       EQU $ffe0 ; シリアル一時レジスタ

; === WRAM Variables ===
DEF LCD_REDRAW        EQU $c61c ; LCD再描画フラグ
DEF BOARD_DATA        EQU $c62a ; 盤面データ開始 (4列×7行)
DEF PLAYER_MODE       EQU $c671 ; プレイヤーモード (0=1P, 1=2P)
DEF PIECE_FALL_POS    EQU $c68f ; ピース落下位置
DEF PIECE_ROTATION    EQU $c691 ; ピース回転状態
DEF MENU_CURSOR       EQU $c6b1 ; メニューカーソル位置
DEF TWO_PLAYER_FLAG   EQU $c6b6 ; 2Pモードフラグ
DEF LINK_RECV         EQU $c6b9 ; リンク受信バイト
DEF LINK_SEND         EQU $c6ba ; リンク送信バイト
DEF LINK_ROLE         EQU $c6bb ; リンクケーブルロール (0=なし, 1=マスター, 2=スレーブ)
DEF SPRITE_ANIM_FRAME EQU $c6cf ; スプライトアニメフレーム
DEF SPRITE_ANIM_STATE EQU $c6d0 ; スプライトアニメ状態
DEF BGM_INDEX         EQU $c6e1 ; BGMインデックス
DEF MENU_SELECT       EQU $c6f0 ; メニュー選択インデックス
DEF GAME_MODE_FLAG    EQU $c6f1 ; ゲームモードフラグ
DEF PAUSE_FLAG        EQU $c707 ; ポーズフラグ

; === Sound Commands ===
DEF SND_STOP_ALL      EQU $ff   ; 全サウンド停止
