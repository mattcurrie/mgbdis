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
- VBlank ($0040): `jp VBlankHandler` → Bank 1 VBlankHandler
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

`$FFC7` レジスタで7つの状態を管理:

```text
Title flow:   State 0 → State 1 → State 6 → State 5 → State 2 → State 3
Round flow:                                      State 3 → State 4 → State 3/0
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

### Drawing ($1203-$12FF, $2147, $2562-$2EB2)

- DrawNumber/DrawDigit/DrawString/DrawStringToGrid/DrawCharacter: テキスト描画
- DrawBox/FillRect: UI矩形描画
- DisplayScore/DisplayLevel/DisplayLines: ステータス表示
- Score/result text tables: `$25C3-$2663`, `$2734-$2853`, `$2CBC-$2EB2`
- Countdown digit pattern table: `$2FFB-$304A`

### 2-Player ($17C5-$18B5, $21C5-$22A8)

- Process2Player/Send2PData: 2P通信ロジック
- SetupMultiplayer/UpdateFieldAnimSlot10-13: フィールド演出用スプライトスロット更新
- SerialHandler ($2092): シリアル割り込み

### Options UI & Settings ($1C4F-$203B)

- DrawOptionTextLabels/DrawOptionMarkers/DrawTileTripletList/ApplySettings/ResetSettings
- Option text/tile tables: `$1D84-$1DBE`, `$1E3D-$1E4F`, `$1F4C-$1F4F`, `$2026-$203A`
- 保存データ署名: $C757-$C75A = ($C7,$8A,$29,$36)

## Bank 1: VBlank, Sprites, Sound

### Sprite System ($4000-$4310)

- **UpdateSprites**: $C200オブジェクトテーブル→$C400 OAMバッファ展開
- **InitSpriteBuffer**: バッファクリア
- DrawLevelDisplayDigits/AdvanceLevelDisplayDigits: レベル表示桁の描画と進行

### Sound Engine ($5187-$5699)

- MusicDataInit/LoadMusicTrack/ParseMusicCommand/ProcessNote/UpdateChannel
- SoundEngine/SoundLookupIndex/StartSoundSequence/StopAllSoundHW/StopAllSound
- Sound support tables: `$5669-$5699`

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

4ハードウェアチャンネル対応 (Square1, Square2, Wave, Noise)。
$C000-$C0ED: サウンドワークRAM。

### Sound Data ($55E2-$7FFF)

音源開始コード、サポートテーブル、音楽/効果音シーケンス、波形データが続く領域。
`$55E2-$5668` は `StartSoundSequence` コード、`$5669-$5699` はサウンド補助テーブル、
`$569A-$7C01` は音楽/効果音シーケンス、`$7C02-$7C07` は短い補助コード、
`$7C2C-$7FFF` はサウンドインデックス、波形、末尾シーケンスデータ。

#### Sound Engine Architecture

```text
SoundEngine ($53C9)
  → MusicDataInit ($5187): トラック初期化
  → LoadMusicTrack ($51B2): 楽曲ポインタテーブルからロード
  → ParseMusicCommand ($51C2): コマンドバイト解析
  → ProcessNote ($51DA): ノート処理 → レジスタ書き込み
  → UpdateChannel ($521F): チャンネル状態更新
```

#### Sound Work RAM ($C000-$C0ED)

| Offset | Size | Description |
|--------|------|-------------|
| $C000 | 1 | `SOUND_STATUS`; reset state, no confirmed reader yet |
| $C001 | 1 | `SOUND_COMMAND_ID`; current sound command/index |
| $C002 | 1 | `SOUND_PAUSE_FLAG`; pause gate, bit 7 marks applied mute |
| $C003-$C005 | 3 | Deferred/nested sound ID, channel output mask, `rNR50` backup |
| $C006-$C015 | 16 | `SOUND_CH_SEQUENCE_PTRS`; 8 current sequence pointers |
| $C016-$C025 | 16 | `SOUND_CH_RETURN_PTRS`; 8 `$FD` return pointers |
| $C026-$C02D | 8 | `SOUND_CH_ACTIVE_ID`; active sound/priority ID |
| $C02E-$C075 | 72 | Per-channel flags, duty, delay, vibrato, and frequency-low state |
| $C076-$C0B5 | 64 | Pitch slide current/target/step state |
| $C0B6-$C0C5 | 16 | Note length and `$FE` loop counters |
| $C0C6-$C0E5 | 32 | Length scale, tempo accumulator, octave, and envelope state |
| $C0E6-$C0ED | 8 | Wave pattern, main/SFX tempo, and temporary sound-index pointer |

#### Music Data Format

楽曲データはポインタテーブル + シーケンスデータ構造:

- **ポインタテーブル** ($7191付近): 各楽曲のシーケンスデータ先頭アドレス (2バイト×曲数)
- **シーケンスデータ**: バイト列で音符/コマンドをエンコード
  - $00-$71: ノートデータ (音高+長さ)
  - $FF: 全サウンド停止コマンド
  - その他: チャンネル制御コマンド

#### Channel Mapping

| Channel | Register Base | Type |
|---------|--------------|------|
| 0 | NR10-NR14 | Square 1 (sweep) |
| 1 | NR21-NR24 | Square 2 |
| 2 | NR30-NR34 | Wave |
| 3 | NR41-NR44 | Noise |
| 4-7 | — | 拡張 (通信/効果音) |

Wave RAM ($FF30-$FF3F) は `LoadWavePattern` ($4BF8) で更新。
WAVE_UPDATE フラグ ($FF9B) が立っている場合 VBlank 中に転送。

## Bank 2-3: Graphics

### Bank 2 ($4000-$7FFF) - Tile Sets

| Address | Label | Size | Description |
|---------|-------|------|-------------|
| $4000 | GameTileSet | $800 (2KB) | ゲーム画面タイル (128タイル) |
| $4800 | CommonTileSet | $1000 (4KB) | 共通タイル (256タイル) |
| $5800 | ExtraTiles | $800 (2KB) | 追加タイル (128タイル) |
| $6000 | TitleTileSet | $1000 (4KB) | タイトル画面タイル |
| $6F70 | TwoPlayerTiles1 | $260 | 2P用タイル1 |
| $71D0 | TwoPlayerTiles2 | $200 | 2P用タイル2 |
| $73D0 | UnusedTileData | $C30 | 未使用タイルデータ |

### Bank 3 ($4000-$7FFF)

追加タイルグラフィックス (16KB全域データ)。現在はロード先ごとの開始ラベルを追加済み。

| Address | Label | Observed use |
|---------|-------|--------------|
| $4000 | Bank3MatchingTilesTo9000 | `ProcessMatching` → VRAM `$9000` |
| $4800 | Bank3MatchingTilesTo8800 | `ProcessMatching` → VRAM `$8800` |
| $4E40 | Bank3MatchingTilesTo8000 | `ProcessMatching` → VRAM `$8000` |
| $5400 | Bank3ResultTilesTo9000 | Result/round setup → VRAM `$9000` |
| $5C00 | Bank3ResultTilesTo8800 | Result/round setup → VRAM `$8800` |
| $5DD0 | Bank3HighScoreTilesTo9000 | High-score/result path → VRAM `$9000` |
| $65D0 | Bank3HighScoreTilesTo8800 | High-score/result path → VRAM `$8800` |
| $6AB0 | Bank3HighScoreOverlayTilesTo9470 | Conditional high-score overlay → VRAM `$9470` |
| $6E40 | Bank3HighScoreOverlayTilesTo8800 | Conditional high-score overlay → VRAM `$8800` |

### Graphics Load Map

Bank 2/3 は通常の実行コードではなく、画面遷移中に一時的に選択される素材バンク。
`MBC1_ROM_BANK_REG` (`$2100`) に `ROM_BANK_GRAPHICS_0` / `ROM_BANK_GRAPHICS_1`
を書き込んで VRAM にコピーし、その後 `ROM_BANK_MAIN_CODE` に戻す。

詳細な転送表はリポジトリルートの `docs/source_recovery/graphics_loads.md` を参照。

## Memory Map

### WRAM ($C000-$DFFF)

| Range | Usage |
|-------|-------|
| $C000-$C0ED | サウンドワークRAM |
| $C200-$C3FF | スプライトオブジェクトテーブル (4 objects × $10 bytes) |
| $C400-$C49F | OAMシャドウバッファ (40 sprites × 4 bytes) |
| $C4A0-$C607 | BGマップシャドウバッファ |
| $C61C | LCD再描画フラグ |
| $C620 | 未確定: スコア領域クリア時に保持される byte |
| $C62A-$C66D | ゲーム盤面データ (4列 × 7行) |
| $C671 | ゲーム種別 (0=A-TYPE系, 1=B-TYPE系) |
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

## Board Data Structure

### Layout ($C62A-$C66D)

4列×7行 = 28バイトのパズル盤面。各バイトがピースIDを保持。

```text
        Col 0   Col 1   Col 2   Col 3
Row 0:  $C62A   $C62B   $C62C   $C62D   ← 最上段
Row 1:  $C62E   $C62F   $C630   $C631
Row 2:  $C632   $C633   $C634   $C635
Row 3:  $C636   $C637   $C638   $C639
Row 4:  $C63A   $C63B   $C63C   $C63D
Row 5:  $C63E   $C63F   $C640   $C641
Row 6:  $C642   $C643   $C644   $C645   ← 最下段
        ...
$C66D:  拡張データ末尾
```

注: 実際のメモリレイアウトには行間にメタデータ/パディングが含まれる可能性あり。
$C62A-$C66D の68バイト中、28バイトがピースデータ、残りはアニメーション状態等。

### Piece IDs

| Value | Meaning |
|-------|---------|
| $00 | 空 |
| $01-$06 | ピース種類 (キャラクター: クリボー、テレサ、パックン、ゲッソー等) |
| 上位bit | 殻の上半分/下半分フラグ |

### Board Operations

| Routine | Address | Description |
|---------|---------|-------------|
| InitGameBoard | $0B7A | 盤面初期化 (全セルをゼロクリア) |
| UpdateBoard | $1655 | 盤面更新 (重力・消去適用) |
| ScanBoard | $168F | 盤面走査 (マッチ検出) |
| CheckMatch | $130C | ピース一致判定 (上下殻ペア) |
| CheckVerticalMatch | $13A8 | 垂直マッチ検出 |
| CheckHorizontalMatch | $13B8 | 水平マッチ検出 |
| ProcessMatch | $13C5 | マッチ処理 (消去アニメ開始) |
| ClearMatchedPieces | $13D5 | マッチしたピースをクリア |

### GameTurnTable ($0C40)

レベル別ゲームターン設定テーブル。660バイト ($294)、4バイト×165エントリ。
各エントリの構造: `[flag, count, type, value]`

- ProcessMatching ($0ED5) から参照され、レベルごとの
  落下速度・ピース出現パターンを制御する。

### Matching Logic

```text
ProcessGameTurn (GameTurnTable参照)
  → CheckMatch: 上下のピースペアを比較
    → CheckVerticalMatch: 列内の垂直マッチ
    → CheckHorizontalMatch: 行内の水平マッチ (2P用)
  → ProcessMatch: マッチしたピースをマーク
  → ClearMatchedPieces: マークされたピースを消去
  → UpdateBoard: 重力適用、空きスペースを詰める
```

## Bank Switching

Bank 0 は常駐。Bank 1-3 は `MBC1_ROM_BANK_REG` (`$2100`) で切り替え:

- MainLoop: Bank 2/3 (グラフィックスロード) → Bank 1 (ゲーム処理)
- VBlankHandler: Bank 1 に戻してから `UpdateSprites`
- PlaySound: Bank 0 → Bank 1 SoundEngine → 復帰

## Build

```bash
cd Yoshi && make
# MD5: 0ccb1e6beb86d79a7a5dad81eb6c73a9
```

Requires RGBDS toolchain (rgbasm, rgblink, rgbfix).

## Statistics

- Named labels: 370+
- Bank 0: ~290 labels (system, game logic, UI) + data tables
- Bank 1: ~80 labels (sprites, sound, VBlank)
- Bank 2: 7 labeled tile sets
- Bank 3: 1 graphics block with 9 transfer-start labels
- Constants: 35+ named HRAM/WRAM/sound definitions
