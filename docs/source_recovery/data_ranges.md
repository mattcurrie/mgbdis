# Recovered Data Ranges

This document tracks source ranges converted from instruction-looking disassembly
to explicit data.

## Bank 1 Sprite Update Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$40A0-$42F4` | `SpriteUpdatePointerTable`, `SpriteFrameTable_*`, `SpriteTileList_*`, and `SpriteLayout_*` | Converted to structured `dw`/`db` | `UpdateSprites` loads `$40A0`, indexes it as a 2-byte object frame-table pointer, then reads each frame as `dw tile_id_list, layout_list`. The next confirmed code label is `UpdateAnimFrame` at `01:$42F5`. |

Notes:

- The pointer table starts at `01:$40A0`.
- Some pointers intentionally point back into the table area, for example `01:$40AE`; this is preserved by placing labels inside the table.
- `docs/source_recovery/sprite_oam.md` records the recovered format: `SpriteUpdatePointerTable` maps object types to frame tables, each frame entry is `dw tile_id_list, layout_list`, and layout lists contain repeated `y_delta, x_delta, attr` triples terminated by attribute bit 0.
- Earlier compatibility `DEF` symbols for fake sprite-data labels were removed after the downstream music streams were converted and no longer referenced them.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 1 Gameplay Field Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$442C-$445B` | `FieldColumnTilePatternTable` | Converted to `db` | `LoadGameBGTiles` shifts `FIELD_COLUMN_TILE_PATTERN_INDEX` left four times, indexes this base address through `GetArrayElement`, then copies exactly 16 bytes to the BG/field destination. The next byte at `01:$445C` is a real code entry, now labeled `StartNextRound`. |

Notes:

- The six records are 16-byte tile patterns using tile `$4A` and marker tiles `$FB/$FC`.
- `StartNextRound` is called from two Bank 0 round-end paths and resets round/egg/transient state before resuming `GAME_STATE_PLAYING`.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 1 Tile Strings

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$462B-$465C` | `SpriteAnimTextFrame0..2` | Converted to `db` string blocks | `AnimateSprite` selects one of three `DE` bases and calls `DrawStringToGrid` four times; each block is four `$FF`-terminated tile rows. |
| `01:$46ED-$46FE` | `TitleLabelTextPlayer`, `TitleLabelTextYoshi` | Converted to `db` strings | `DrawTitleLabels` loads each address into `DE` and calls `DrawStringToGrid`; the next byte at `01:$46FF` is the real `ProcessTitleInput` code entry. |

Notes:

- These ranges were previously decoded as instruction-looking bytes because the disassembly did not know the `DrawStringToGrid` string contract.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 1 Sound Engine Code and Tables

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$55E2-$5668` | `StartSoundSequence` | Converted from `db` to code | `SoundEngine` and `SoundLookupIndex` both jump to `$55E2`. The bytes form a coherent routine that expands the selected sound entry from `$7C2C` into the `$C006/$C016/$C026...` sound channel state arrays and returns at `$5668`. |
| `01:$5669` | `SoundWaveDutyData` | Split from sound blob | `StartSoundSequence` stores `$5669` into `$C012/$C013` for later sound processing. |
| `01:$566A-$5671` | `SoundRegisterOffsetTable` | Split from sound blob | `SoundUpdate3` indexes this 8-byte table to compute an `rNRxx` HRAM register address. |
| `01:$5672-$5679` | `SoundChannelDisableMaskTable` | Split from sound blob | `MusicDataInit` indexes this table while masking `rNR51`. |
| `01:$567A-$5681` | `SoundChannelEnableMaskTable` | Split from sound blob | `MusicDataInit` indexes this table while enabling/mixing channels in `rNR51`. |
| `01:$5682-$5699` | `SoundPitchBaseTable` | Split to `dw` | `SoundUpdate5` indexes this table as 12 16-bit pitch/frequency base values. The following `$569A` byte is a real sequence entry target from `SoundIndexTable`, not part of the pitch table. |
| `01:$569A-$5FE2` | `SoundSequenceData_569a` through `SoundSequenceData_5f30` | Labeled existing `db` with internal boundaries | This range was already represented as `db`, but it was one large block and started two bytes too late. `$FD/$FE` pointer targets and sound-index targets now have labels. |
| `01:$5FE3-$7190` | `MusicSequenceData_5fe3` through `MusicSequenceData_6f92` | Converted to `db` | `Yoshi/yoshi.sym` marks `$5FE3` as `.code:100`, but no real code references remain. The range is a dense music-command stream with many `$FD/$FE` pointer targets and joins the existing music data at `$7191`. |
| `01:$7191-$71C0` | `MusicSequenceData_7191` | Labeled existing `db` | `Yoshi/yoshi.sym` marks this exact range as `.data:30`; the current source already stored the bytes as `db`, so this step adds the missing boundary label. |
| `01:$71C1-$71E3` | `MusicSequenceData_71c1`, `MusicSequenceData_71c2`, `MusicSequenceData_71d5` | Converted to `db` | `Yoshi/yoshi.sym` marks this short range as `.code:2f`, but it sits between confirmed music data blocks, contains `$FD/$FE` music pointers, and has only fake cross-references from still-unconverted music data. |
| `01:$71E4-$77B5` | `MusicSequenceData_71e4` through `MusicSequenceData_779b` | Converted to `db` | This larger stream spans the earlier `MusicSequenceData_71e4`, the fake-code `$73B3` island, and the following instruction-looking bytes up to `$77B5`. It contains dense music command bytes and `$FD/$FE` internal pointers, with no confirmed real code entry inside the range. |
| `01:$77B6-$7805` | `MusicSequenceData_77b6`, `MusicSequenceData_77c5` | Converted to `db` | `Yoshi/yoshi.sym` marks this exact range as `.code:50`, but the apparent calls into `$77B6/$77C5` come from music-data bytes decoded as instructions. The range contains repeated sequence bytes and pointer-like operands consistent with the neighboring music stream. |
| `01:$7806-$7C01` | `MusicSequenceData_7806` through `MusicSequenceData_7be7` | Converted to `db` | The range directly follows the recovered `$77B6-$7805` sequence block and contains music commands, local `$FD/$FE` pointer targets, repeated `$FF` terminators, and no real code references. The next six bytes at `$7C02-$7C07` are real code and are deliberately excluded. |
| `01:$7C2C-$7D84` | `SoundIndexTable`, `SoundIndexEntry_*` | Converted to `db`/`dw` | `SoundLookupIndex` and `StartSoundSequence` compute `index * 3 + $7C2C`; each entry is one flags/channel byte and one little-endian sequence pointer. |
| `01:$7D85-$7DBC` | `SoundSequenceData_7d85` through `SoundSequenceData_7db9` | Converted to `db` | These short sequence entries are direct targets of early `SoundIndexTable` entries. |
| `01:$7DBD-$7DCE` | `WavePatternPointerTable` | Converted to `dw` | `ProcessNote` indexes `$7DBD` with the wave selector and copies 16 bytes from the selected pointer to wave RAM. |
| `01:$7DCF-$7FFE` | `WavePatternData_*`, `SoundSequenceData_*` | Converted to `db` | Contains three dedicated wave patterns, a shared `$7DFF` wave/sequence entry, and the remaining sound-index sequence targets through `$7FFE`. |

Notes:

- Earlier notes treated all of `01:$55E2-$5FE2` as sound data. That was too broad: the entry at `$55E2` is executable code reached by real jumps.
- The sequence data beginning at `SoundSequenceData_569a` is now explicit `db` with first-pass pointer-target and sound-index labels. Full command decoding and track naming still remain.
- `WavePatternData_7dff` and `SoundSequenceData_7dff` intentionally share the same address because the wave pointer table and sound index table both target `$7DFF`.
- Temporary compatibility `DEF` symbols for fake music-data references were removed after the referencing streams were converted to explicit data.
- `01:$7C02-$7C07` is not part of the music stream. Bank 0 calls it twice, and it is now labeled `TickBgmPreviewTimer`.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 0 Gameplay Tables

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$0B8D-$0ED2` | `GameTurnParamTable` | Labeled full table; converted fake-code head to `db` | `DrawMenuCursor` seeds `GAME_TURN_TABLE_INDEX` from `LevelThresholds`, and both it and `ProcessMenuLoop` compute `GameTurnParamTable + index * 4`. The first byte reloads `GAME_TURN_STEP_TIMER`, the second reloads `PIECE_DISPLAY_COUNT` / `DisplayResults`, and the third reloads `GAME_TURN_DELAY`. |
| `00:$117C-$119B` | `MatchingOamTemplateTop`, `MatchingOamTemplateMiddle`, `MatchingOamTemplateFinal` | Converted to `db` OAM templates | `ProcessMatching` copies the middle template to `$C408`; the later matching/result animation copies the top and final templates to `$C400`. Each record is standard four-byte OAM layout data. |
| `00:$119C-$11D3` | `MatchingScoreBonusTable` | Converted to `db` big-endian BCD pairs | `UpdateScore` indexes this table with `STATE_TRANSITION * 2`, loads the first byte into `H` and second byte into `L`, then calls `AddScore`. |
| `00:$11D4-$11EF` | `MatchingTileBaseIndexTable` | Converted to `db` | `ProcessMatching` and the later matching/result animation index this 28-byte table with `STATE_TRANSITION`, then scale the value to choose result sprite tile IDs. |
| `00:$15FE-$1611` | `LevelFallDelayTable` | Converted to `db` | `ProcessFalling` loads this address, caps active level to `$13`, and calls `GetArrayElement`; the result seeds the fall timer at `$C6A7`, halved when `ACTIVE_SPEED` is nonzero. |
| `00:$18CB-$18D1` | `RoundCompleteStateRemapTable` | Converted to `db` | `UpdateTimer` indexes this table with `SCREEN_STATE` and writes the result back to `SCREEN_STATE` before building the 2P/OAM state packet. |
| `00:$18D2-$18E3` | `RoundCompleteDelayParamTable` | Converted to `db` big-endian word pairs | The round-complete path indexes this table with `ROUND_COMPLETE_PARAM_INDEX * 2`, loads the first byte into `H` and second byte into `L`, then calls `AddScore`. `CalcResults` starts immediately after at `00:$18E4`. |
| `00:$22CC-$230E` | `FieldSideDeltaTable` | Converted to `db` | `StepFieldAnimSlot11SideDelta` and `StepFieldAnimSlot10SideDelta` index this table with `FIELD_ANIM_SLOT_11_CURSOR` / `FIELD_ANIM_SLOT_10_CURSOR` to step object slots 11 and 10 until terminator `$10`. |
| `00:$230F-$234B` | `FieldRowDeltaTable` | Converted to `db` | `StepFieldAnimSlot13RowDelta` and `StepFieldAnimSlot12RowDelta` index this table with `FIELD_ANIM_SLOT_13_CURSOR` / `FIELD_ANIM_SLOT_12_CURSOR`; the next byte at `00:$234C` is the restored `UpdateFieldTimers` code entry. |

Notes:

- `GameTurnParamTable_0c40` is only an internal exact-address landmark inside the same 4-byte stride table; the actual indexed base is `GameTurnParamTable` at `00:$0B8D`.
- `00:$11F0` is deliberately left as code and labeled `UnusedDrawNumberPairUnlessFF`; no confirmed direct caller has been found, but the bytes form a coherent helper and are not part of the matching tables.
- `00:$1612` is not table data. It is a real code entry called by `UpdateMatchState`, now labeled `UpdateLandingProgress`, and falls through to `CommitFallingPieceToBoard` at `00:$162A`.
- The previous disassembly decoded bytes across the `00:$15FE-$1611` table and the `00:$1612` code entry as one misleading instruction stream.
- The previous disassembly also decoded `00:$18CB-$18E3` as instructions after `HandlePieceLanding`, even though both `$18CB` and `$18D2` have direct table references.
- The previous disassembly decoded `00:$22CC-$234B` as instructions, making real calls to `00:$234C` appear to target the middle of an instruction stream.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 0 Graphics Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$3839-$3D38` | `TitleResultTileData0` | Converted to `db` | Result/title setup loads `DE=$3839`, `HL=$8820`, `C=$50`, then calls `VRAMCopySetup`, copying 80 16-byte tiles. |
| `00:$3D39-$3E48` | `TitleResultTileData1` | Converted to `db` | The same path loads `DE=$3D39`, `HL=$9140`, `C=$11`, then calls `VRAMCopySetup`, copying 17 16-byte tiles. |
| `00:$3E49-$3FFF` | `Bank0TailGraphicsData` | Converted to `db` | Remaining ROM0 tail is graphics/padding-like data. Converting it removes fake `jr_000_39*`/`jp $7cc3` code labels while preserving the exact bytes. |

Notes:

- The `00:$3839-$3FFF` conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.
- `TitleResultTileData0` and `TitleResultTileData1` are named from confirmed VRAM-copy source addresses; exact screen/art role can be refined after visual tile mapping.

## Bank 0 Option UI Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$1D84-$1DAE` | `OptionTextAGame` through `OptionTextOff` | Converted to `db` strings | `DrawOptionTextLabels` loads each address into `DE` and calls `DrawStringToGrid`; bytes are `$FF`-terminated tile strings for `A GAME`, `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, and `OFF`. |
| `00:$1DAF-$1DBE` | `OptionMarkerPositions` | Converted to `db` coordinate pairs | `DrawOptionMarkers` iterates eight row/column pairs, calls `CalcTilemapAddress`, clears each marker tile, then draws the active marker. |
| `00:$1E3D-$1E4F` | `SettingsCursorTileData` | Converted to `db` triplets | `DrawTileTripletList` consumes row/column/tile triples until `$FF`; `UpdateCursorDisplay` uses this list to draw the inactive cursor tiles. |
| `00:$1E75-$1E89` | `SettingsCursorSpriteInit0..2` | Converted to `db` records | `ApplySettings` copies three fixed 7-byte records to `$C290`, `$C2A0`, and `$C2B0`. |
| `00:$1F4C-$1F4F` | `OptionMaxValueTable` | Converted to `db` limits | Option increment code indexes this four-byte table with `MENU_CURSOR` before accepting a right-button change. |
| `00:$2026-$203A` | `SettingsCursorTileData0..2` | Converted to `db` triplet lists | `SaveConfig1..3` pass these addresses to `DrawTileTripletList` to draw the highlighted cursor row. |
| `00:$254E-$254F` | `LinkSettingsMaxValueTable` | Converted to `db` limits | `Run2PPreplayLoop` indexes this two-byte table with `LINK_SETTINGS_CURSOR` before accepting a right-button change to 2P level or speed. |
| `00:$2B9D-$2BA0` | `RoundPaletteSequence` | Converted to `db` palette bytes | `SetRoundSpeed` reads four bytes from this table, writes each to `rBGP`, and calls `DrawString` with `C=$10` after each palette step. |
| `00:$2C60-$2C63` | `RoundEndOptionMaxValueTable` | Converted to `db` limits | `Run1PPreplayLoop` uses the same four option-row limits in the result/start-wait path. |

Notes:

- The old labels `UpdatePaletteFade`, `UpdateHighScore`, `LoadSettings`, and `SaveSettings` were misleading for this area. They are now named `DrawOptionTextLabels`, `DrawOptionMarkers`, `DrawOptionMarker`, and `DrawTileTripletList`.
- The byte at `00:$203B` is still an explicit `ret` immediately before `DrawOptionValues`; it is not part of the three highlighted cursor triplet lists.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 0 Score/Result Text Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$25C3-$25E0` | `ScoreHeaderTextRole1`, `ScoreHeaderTextRoleOther` | Converted to `db` strings | `DrawScoreDigits` selects one of the two `$FF`-terminated strings based on `LINK_ROLE`, then calls `DrawStringToGrid`. |
| `00:$2622-$2663` | `ResultTextBlock0..2` | Converted to `db` two-line strings | `CalcBonus` and `ShowWinScreen` select these blocks, then call `DrawStringToGrid` twice; each block contains two `$FF`-terminated lines. |
| `00:$2CBC-$2CD6` | `ResultHeaderText` | Converted to `db` two-line string | `ProcessWinLose` draws the header through `DrawStringToGrid`; the text decodes as `1 PLAYER GAME` / `YOSSY EGGS`. |
| `00:$2DE0-$2E2D` | `RestartTextBlock0..2` | Converted to `db` two-line strings | `ProcessRestart` selects one of three blocks, then calls `DrawStringToGrid` twice. |
| `00:$2E38-$2E3B` | `ContinueOffText` | Converted to `db` string | `DrawContinue` draws this `$FF`-terminated duplicate of `OFF`. |
| `00:$2E7C-$2EB2` | `BgmMarker0Text..BgmMarkerNoneText` | Converted to `db` marker strings | `UpdateContinue` selects one `$9A` marker line, or an all-space line, then calls `DrawStringToGrid`. |
| `00:$2734-$2853` | `PiecePreviewTextTable`, `PiecePreviewText0..4`, `PiecePreviewBlankText` | Converted to `db` three-line tile strings | `DrawPreview` and `WaitForRestart` index this table with `a * 48`, then call `DrawStringToGrid` three times; each entry is three 16-byte `$FF`-terminated rows. |
| `00:$2FFB-$304A` | `CountdownDigitPatternTable`, `CountdownDigitPattern0..9` | Converted to `db` digit bitmaps | `UpdateCountdownTimer` indexes this table after shifting BCD-like countdown nibbles; each digit record is 8 bytes and the routine copies 7 visible rows. |

Notes:

- These blocks were all previously decoded as instructions because the disassembly did not know the `DrawStringToGrid` data contract.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Remaining High-Value Data Cleanup

| Range | Reason |
|-------|--------|
| Bank 1 sound/music command semantics | The byte streams now have boundaries, but the command names, track grouping, and channel roles still need a dedicated format pass. |
| Other Bank 0 inline tables | Some unrelated rows still show instruction-looking bytes that may be data. Convert only after exact call/index boundaries are confirmed. |
