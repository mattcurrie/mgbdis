# YOSSY NO TAMAGO (Yoshi's Egg) - Architecture

Game Boy puzzle game. ROM: 64KB (4 banks × 16KB). CPU: SM83 (Sharp LR35902).

## ROM Layout

| Bank | Address | Size | Contents |
|------|---------|------|----------|
| 0 | $0000-$3FFF | 16KB | System, game logic, state machine, UI |
| 1 | $4000-$7FFF | 16KB | VBlank handler, sprites, sound engine, music data |
| 2 | $4000-$7FFF | 16KB | Tile graphics (game, title, common) |
| 3 | $4000-$7FFF | 16KB | Additional tile graphics |

## Bank 0: System & Game Logic

### Entry & Interrupts ($0000-$0100)

- RST vectors ($00-$38): Unused (rst $38)
- VBlank ($0040): `jp $4b59` → Bank 1 VBlankHandler
- STAT ($0048): `reti`
- Timer ($0050): `reti`
- Serial ($0058): `jp SerialHandler` → 2P通信
- Joypad ($0060): `reti`
- $0068: PositionTable (152 bytes, X/Y coordinate pairs)
- $0100: EntryPoint → `jp Init`

### System Routines ($0150-$0260)

| Address | Label | Description |
|---------|-------|-------------|
| $0150 | ReadJoypad | P1レジスタ→$FFA0-$FFA2 |
| $01BA | SetupOAMDMA | 10バイトDMAルーチンをHRAM $FF80にコピー |
| $01D2 | LCDOff | VBlank待ち→LCD無効化 |
| $01E9 | LCDOn | LCD有効化 |
| $01F0 | ClearOAM | OAMバッファゼロクリア |
| $020B | Memcopy | HL→DE, BCバイト転送 |
| $0223 | VRAMCopySetup | 分割VRAM転送パラメータ設定 |

### State Machine ($026B-$035C)

`$FFC7` レジスタで6つの状態を管理:

```text
State 0 → State 1 → State 2 → State 3 → State 4 → (loop)
  │                              │                    │
  └──────────────────────────────┘     State 5 ←──────┘
                                       State 6 → State 3
```

| State | Function | Description |
|-------|----------|-------------|
| 0 | StateInit | タイトル画面初期化 (Bank 2 タイルロード) |
| 1 | (MainLoop) | タイトル画面入力待ち |
| 2 | (MainLoop) | ゲーム画面初期化 (タイル・フィールド構築) |
| 3 | (MainLoop) | ゲームプレイ (HandlePause + GameMainUpdate) |
| 4 | (MainLoop) | ラウンド終了 (HandleRoundEnd) |
| 5 | (MainLoop) | オプション画面 (OptionsScreen) |
| 6 | (MainLoop) | ゲーム開始遷移 (追加グラフィックス) |

### Game Logic ($0C40-$1A00)

- **ProcessGameTurn** ($0C40): ターン処理メインルーチン
- **ProcessMatching** ($0E84): 5段階マッチアニメーション
  1. LCD OFF
  2. グラフィクスロード
  3. アニメーション1 (136フレーム)
  4. アニメーション2 (10フレーム)
  5. 結果表示
- **CheckMatch** ($130C): ピース一致判定 (上下入れ替え)
- **ProcessInput** ($152F): 入力→移動・回転・ドロップ
- **UpdateBoard** ($1655): 盤面更新
- **UpdateFallTimer** ($173A): 落下タイマー管理

### Piece System

4列×7行の盤面。ピースは上から落下し、上下半殻のペアでマッチング:

- MovePieceDown/Up/Left/Right: 移動
- RotatePiece: 回転
- DropPiece/HandleDrop: 高速落下
- GenerateNextPiece/GetRandomPiece: 次ピース生成

### Drawing ($1203-$12FF, $2562-$26FF)

- DrawNumber/DrawDigit/DrawString/DrawCharacter: テキスト描画
- DrawBox/FillRect: UI矩形描画
- DisplayScore/DisplayLevel/DisplayLines: ステータス表示

### 2-Player ($17C5-$18B5, $21C5-$22A8)

- Process2Player/Send2PData: 2P通信ロジック
- SetupMultiplayer/SetupLinkCable: リンクケーブル初期化
- SerialHandler ($2092): シリアル割り込み

### Settings & Save ($1E26-$1E92)

- LoadSettings/SaveSettings/ApplySettings/ResetSettings
- 保存データ署名: $C757-$C75A = ($C7,$8A,$29,$36)

## Bank 1: VBlank, Sprites, Sound

### Sprite System ($4000-$4310)

- **UpdateSprites**: $C200オブジェクトテーブル→$C400 OAMバッファ展開
- **InitSpriteBuffer**: バッファクリア
- SpriteAnimTable/AnimFrameData: アニメーションテーブル

### VBlank Handler ($4B59)

毎フレーム実行。処理順序:

1. ProcessFieldLogic - フィールドロジック
2. RandomNext - 乱数更新
3. VRAMCopyDMA - VRAM転送
4. $FF80 (OAM DMA) - スプライト転送
5. TimerTickCore - タイマー
6. UpdateSprites - スプライト更新
7. スクロール/ウィンドウレジスタ更新
8. 通信処理 (2Pモード時)

### WaitVBlank ($4BC5)

$FFC5フラグ+haltループでVBlank同期待ち。

### Sound Engine ($53C9-$55DB)

コマンドベースのサウンドエンジン:

- A=$FF: 全サウンド停止 (StopAllSound→StopAllSoundHW)
- A=$00-$71: BGM/SE再生

処理フロー:
```text
SoundEngine → MusicDataInit → ParseMusicCommand → ProcessNote → UpdateChannel
                                                       ↓
                                              LoadWavePattern (Wave RAM)
```

4チャンネル対応 (Square1, Square2, Wave, Noise)。
$C000-$C09E: サウンドワークRAM。

### Sound Data ($55E2-$7FFF)

音楽シーケンスデータ。コードとデータが混在する領域あり。

## Bank 2-3: Graphics

- Bank 2 ($4000-$7FFF): ゲーム画面/タイトル/共通/2Pタイルセット
- Bank 3 ($4000-$7FFF): 追加タイルグラフィックス

## Memory Map

### WRAM ($C000-$DFFF)

| Range | Usage |
|-------|-------|
| $C000-$C09E | サウンドワークRAM |
| $C200-$C3FF | スプライトオブジェクトテーブル (4 objects × $10 bytes) |
| $C400-$C4FF | OAMシャドウバッファ (40 sprites × 4 bytes) |
| $C61C | LCD再描画フラグ |
| $C620 | レベルカウンタ |
| $C62A-$C66D | ゲーム盤面データ (4列 × 7行) |
| $C671 | プレイヤーモード (0=1P, 1=2P) |
| $C6B6 | 2Pモードフラグ |
| $C6BB | リンクケーブル役割 (0=なし, 1=マスター, 2=スレーブ) |
| $C6E1 | BGMインデックス |
| $C707 | ポーズフラグ |
| $C757-$C75A | セーブ署名 |

### HRAM ($FF80-$FFFF)

| Range | Usage |
|-------|-------|
| $FF80-$FF89 | OAM DMAルーチン |
| $FF8A | アニメフレームカウンタ |
| $FF8B | 状態遷移フラグ |
| $FFA0-$FFA2 | ジョイパッド状態 |
| $FFA5 | ゲームアクティブフラグ |
| $FFAE-$FFB7 | VRAMコピーパラメータ |
| $FFC5 | VBlank同期フラグ |
| $FFC7 | ステートマシンインデックス |
| $FFC8 | シリアル転送完了フラグ |

## Bank Switching

Bank 0 は常駐。Bank 1-3 は $2100 レジスタで切り替え:

- MainLoop: Bank 2 (グラフィックスロード) → Bank 1 (ゲーム処理)
- VBlankHandler: Bank 1 に固定 (割り込み中)
- PlaySound: Bank 0 → Bank 1 SoundEngine → 復帰

## Build

```bash
cd Yoshi && make
# MD5: 0ccb1e6beb86d79a7a5dad81eb6c73a9
```

Requires RGBDS toolchain (rgbasm, rgblink, rgbfix).

## Statistics

- Named labels: 368
- Bank 0: ~290 labels (system, game logic, UI)
- Bank 1: ~80 labels (sprites, sound, VBlank)
- Bank 2-3: 2 labels (data blocks)
