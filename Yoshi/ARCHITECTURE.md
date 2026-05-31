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
| 3 | (MainLoop) | ゲームプレイ (HandlePause + RunGameplayFrame) |
| 4 | (MainLoop) | ラウンド終了 (HandleRoundEnd) |
| 5 | `GAME_STATE_PREPLAY_LOOP` | `RunPreplayLoop`: 1P/2P pre-play settings and start-wait loop |
| 6 | `GAME_STATE_PREPLAY_INIT` | pre-play graphics/setup via `StartGameplay`, then state 5 |

### Game Logic ($0B8D-$1A77)

- **GameTurnParamTable** ($0B8D): A-type piece-display timing/count table
- **ProcessMatching** ($0ED5): matching/result-panel animation
  1. LCD OFF
  2. グラフィクスロード
  3. アニメーション1 (136フレーム)
  4. アニメーション2 (10フレーム)
  5. 結果表示
- **UpdateGameplayObjectsAndCheckBTypeClear** ($124A): active piece-object update plus B-type clear detection
- **HandlePlayfieldInput** ($130C): input for drop start, cursor movement, and fast-fall clamp
- **UpdateFallingPieceMotionAndLanding** ($13E2): staged piece fall/landing/game-over path
- **CommitFallingPieceToBoard** ($162A): commit path for scan-target payloads
- **RunBoardScanTriggerSequence** ($168F): scan-trigger animation, reward, and round-transition path
- **UpdatePieceFallTimer** ($1294): falling-piece timer owner

### Piece System

4列の盤面。`BOARD_DATA` は 4 個の 16-byte column blocks で、各列の odd byte が
7 visible payload cells として `DrawGridPiece` に渡される。paired even byte は
current live source では piece payload として読まれない。

- `HandlePlayfieldInput`: drop start, cursor left/right, and Down-held fast-fall clamp
- `StartDropColumnSwapAnimation` / `AnimateDropping`: selected-column swap/drop animation
- `UpdateFallingPieceMotionAndLanding`: falling sprite-object motion and landing
- `StagePiecePayloadInSelectedColumn`: writes the staged visible payload into the selected column
- `BuildPieceDisplayStatesForCount` / `BuildPieceDisplayObjects`: next-piece display object state

### Drawing ($1203-$12FF, $2147, $2562-$2EB2)

- DrawStringToGrid: `$FF` terminated tile strings
- FillBytesWithD/FillRect/FillTilemapRectByCoord: BG/OAM/tilemap fill helpers
- WaitVBlankFrames: frame delay helper
- ShiftMatchingOamPairX/ClearManualOamPair/AddScoreAndAnimateManualOamPair: matching/result/round-complete OAM helpers
- ReloadGameTilesAndRequestRedraw: restore game tiles and request sprite redraw
- DrawOptionBoxAtCoord/FillRect: UI rectangle drawing
- DrawScoreRanking/DrawLevelDisplayDigits/DrawPlayfieldRoundTimerDigits: score, level, and timer display
- Score/result text tables: `$25C3-$2663`, `$2734-$2853`, `$2CBC-$2EB2`
- Countdown digit pattern table: `$2FFB-$304A`

### 2-Player ($17C5-$18B5, $21C5-$22A8)

- SendRoundTransitionPreFrame1/Send2PData: 2P通信ロジック
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

### Sound Engine ($4C91-$5668)

- UpdateSoundChannels/TickSoundChannel/SoundSequenceStep/ProcessSoundNoteCommand/UpdateChannel
- SoundEngine/SoundLookupIndex/StartSoundSequence/StopAllSoundHW/StopAllSound
- Sound support tables: `$5669-$5699`

### VBlank Handler ($4B59)

毎フレーム実行。処理順序:

1. CopyNextBgMapShadowSlice - `BG_MAP_SHADOW` の6行スライスをBG map VRAMへ転送
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
SoundEngine → SoundLookupIndex → StartSoundSequence
UpdateSoundChannels → TickSoundChannel → SoundSequenceStep → ProcessSoundNoteCommand
                                                           ↓
                                                  ProcessNote / UpdateChannel
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
  → SoundLookupIndex ($54A1): sound index expansion
  → StartSoundSequence ($55E2): sequence pointer installation
  → SoundSequenceStep ($4D4E): sequence command parsing
  → ProcessSoundNoteCommand ($509C): note/rest command handling
  → ProcessNote ($51DA): ノート処理 → レジスタ書き込み
  → UpdateChannel ($521F): チャンネル状態更新
```

#### Sound Work RAM ($C000-$C0ED)

| Offset | Size | Description |
|--------|------|-------------|
| $C000 | 1 | `SOUND_STATUS`; reset state, no confirmed reader yet |
| $C001 | 1 | `SOUND_COMMAND_ID`; current sound command/index |
| $C002 | 1 | `SOUND_PAUSE_FLAG`; `SOUND_PAUSE_FLAG_ACTIVE` pause gate, bit 7 marks applied mute |
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
| $5800 | PreplayMenuOverlayTiles | $800 (2KB) | pre-play/menu overlay tiles (128 tiles) |
| $6000 | TitleTileSet | $1000 (4KB) | タイトル画面タイル |
| $6F70 | TwoPlayerNonMasterTiles | $260 | non-master-only 2P tile fragment |
| $71D0 | TwoPlayerSharedTiles | $200 | shared 2P tile fragment |
| $73D0 | Bank2UnusedTailTileData | $C30 | unused Bank 2 tail tile/padding data |

### Bank 3 ($4000-$7FFF)

追加タイルグラフィックス (16KB全域データ)。`Bank3GraphicsData` の中に、
ロード先ごとの開始ラベルを追加済み。

| Address | Label | Observed use |
|---------|-------|--------------|
| $4000 | Bank3GraphicsData | full Bank 3 graphics data block |
| $4000 | Bank3MatchingTilesTo9000 | `ProcessMatching` → VRAM `$9000` |
| $4800 | Bank3MatchingTilesTo8800 | `ProcessMatching` → VRAM `$8800` |
| $4E40 | Bank3MatchingTilesTo8000 | `ProcessMatching` → VRAM `$8000` |
| $5400 | Bank3ResultRecordTilesTo9000 | `SetupResultRecordScreen` → VRAM `$9000` |
| $5C00 | Bank3ResultRecordTilesTo8800 | `SetupResultRecordScreen` → VRAM `$8800` |
| $5DD0 | Bank3LinkResultTilesTo9000 | Link-result path → VRAM `$9000` |
| $65D0 | Bank3LinkResultTilesTo8800 | Link-result path → VRAM `$8800` |
| $6AB0 | Bank3LinkResultOverlayTilesTo9470 | Conditional link-result overlay → VRAM `$9470` |
| $6E40 | Bank3LinkResultOverlayTilesTo8800 | Conditional link-result overlay → VRAM `$8800` |

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
| $C200-$C2FF | `SPRITE_OBJECTS`: 16 logical sprite object slots × $10 bytes |
| $C300-$C3FF | Sprite/field-adjacent work area, not fully mapped yet |
| $C400-$C49F | OAMシャドウバッファ (40 sprites × 4 bytes) |
| $C4A0-$C607 | BGマップシャドウバッファ |
| $C61C | LCD再描画フラグ |
| $C620 | 未確定: スコア領域クリア時に保持される byte |
| $C62A-$C669 | `BOARD_DATA`: four 16-byte board column blocks |
| $C66A-$C66D | `COLUMN_TOP_ROWS`: top-row state for the four columns |
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

4 columns × 16 bytes。各 column block の odd offsets (`+1,+3,...,+D`) が
7 visible payload cells として描画・着地・scan path で使われる。

```text
Column 0: $C62A-$C639, visible payloads at $C62B,$C62D,...,$C637
Column 1: $C63A-$C649, visible payloads at $C63B,$C63D,...,$C647
Column 2: $C64A-$C659, visible payloads at $C64B,$C64D,...,$C657
Column 3: $C65A-$C669, visible payloads at $C65B,$C65D,...,$C667
```

`ClearBoardData` clears `$40` bytes from `$C62A`; `$C66A-$C66D` are the
four `COLUMN_TOP_ROWS` bytes. The paired even byte in each two-byte board cell
is currently documented as an unread pair byte, not as live piece state.

### Piece IDs

| Value | Meaning |
|-------|---------|
| $00 | 空 |
| $01-$06 | visible piece payloads with direct `GridPiecePatternPiece1..6` records |
| $07 | `BOARD_SCAN_TRIGGER_PAYLOAD` |
| $08 | `BOARD_SCAN_TARGET_PAYLOAD` |

### Board Operations

| Routine | Address | Description |
|---------|---------|-------------|
| ClearBoardData | $1508 | clears the 64-byte board data region |
| FillInitialBoardColumns | $1549 | B-type initial board fill |
| SpawnFieldColumnEffect | $1655 | 盤面列エフェクトを logical sprite slot 10-13 に生成 |
| RunBoardScanTriggerSequence | $168F | scan trigger payload sequence |
| CommitFallingPieceToBoard | $162A | commits staged scan-target payload and adds commit score |
| StagePiecePayloadInSelectedColumn | $1484 | decrements remaining-piece state and writes staged payload into the selected column |
| ReadBoardCellAtColumnRow | $1758 | reads a selected column/row cell through the 16-byte column stride |

### GameTurnParamTable ($0B8D)

`GameTurnParamTable` is the A-type piece-display schedule. The current source
models it as `GAME_TURN_PARAM_RECORD_COUNT` four-byte records.

- `LoadGameTurnPieceDisplayStep` indexes it with `GAME_TURN_TABLE_INDEX * 4`.
- The first byte feeds the piece-display delay, the second feeds
  `PIECE_DISPLAY_COUNT` and `PIECE_DISPLAY_REMAINING`.
- The third byte is the display code/control byte.
- The fourth byte is still named as an unread tail value because no confirmed
  consumer reads `GAME_TURN_PARAM_UNREAD_TAIL_OFFSET`.

### Matching Logic

```text
RunGameplayFrame
  → HandlePlayfieldInput
  → UpdateGameplayObjectsAndCheckBTypeClear
    → UpdateSpriteObject
      → UpdateFallingPieceMotionAndLanding
        → RunBoardScanTriggerSequence / CommitFallingPieceToBoard / DrawLandedPieceAndUpdateColumnTop
  → AnimateDropping / DrawFieldColumnTilePattern / UpdateFieldTimers
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

- Named labels: about 1,600 in `Yoshi/yoshi.sym`
- Constants: about 1,200 `DEF` entries
- Bank 0/1 generated local labels and raw direct branches: 0 in the current recovery audit
- Bank 2: 7 labeled tile sets
- Bank 3: 1 graphics block with 9 transfer-start labels
