# Recovered Data Ranges

This document tracks source ranges converted from instruction-looking disassembly
to explicit data.

## Current Bank 0/1 Boundary Audit

The known Bank 0/1 code/data misclassifications have now been split in both the
source and `Yoshi/yoshi.sym`. The remaining `.code` directives in these banks
are intentional executable islands: reset/interrupt vectors at `00:$0000`,
the copied OAM DMA HRAM routine at `00:$01C8`, `StartSoundSequence` at
`01:$55E2`, `TickBgmPreviewTimer` at `01:$7C02`, and
`ApplySoundVisualUpdateCommand` at `01:$7C08`.

The converted `.data` ranges cover the previously misleading table, text,
graphics, sprite, and music streams listed below. The current audit checks are:
no overlapping Bank 0/1 `.code`/`.data` blocks in `Yoshi/yoshi.sym`, no
remaining generated `jr_000_*` labels in Bank 0/1, no raw direct branch targets
such as `call $xxxx` / `jp $xxxx` / `jr $xxxx`, and a byte-identical rebuild
against `Yoshi/yoshi.gb`.

## Bank 0 System Padding

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$0104-$014F` | `HeaderLogo` through `HeaderGlobalChecksum` | Explicit cartridge header data | The entry point at `00:$0100` jumps to `Init`; the following fixed Game Boy cartridge header range contains the Nintendo logo, `YOSSY NO TAMAGO` title, cartridge metadata, complement check, and global checksum. `HeaderLogo` now emits RGBDS's built-in `NINTENDO_LOGO` macro, the title bytes remain literal, and the metadata fields from new-licensee bytes through global checksum use named `HEADER_*` constants. `Yoshi/yoshi.sym` marks the same `$4C` bytes as data and keeps the source/header labels in sync with `Yoshi/game.sym`. |
| `00:$0068-$00FF` | `UnusedInterruptVectorPadding` | Explicit unused padding data | This range sits between the Joypad interrupt vector (`00:$0060-$0067`) and the cartridge entry point (`00:$0100`). No source or symbol reference targets the old label, and the bytes are represented as 67 repeated little-endian `$3900` words, one `$0000` word, and 8 final `$3900` words. |

## Bank 1 Sprite Update Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$40A0-$42F4` | `SpriteUpdatePointerTable`, `SpriteFrameTable_*`, `SpriteTileList_*`, and `SpriteLayout_*` | Converted to structured `SPRITE_OBJECT_FRAME_TABLE`/`SPRITE_FRAME_RECORD`/`SPRITE_TILE_LIST_N`/`SPRITE_LAYOUT_ENTRY` | `UpdateSprites` loads `$40A0`, indexes it as a 2-byte object frame-table pointer, then reads each frame as a four-byte `SPRITE_FRAME_RECORD tile_id_list, layout_list`. Tile-id streams are emitted as `SPRITE_TILE_LIST_N` records, and layout streams are emitted as `SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr` triples. The next confirmed code label is `Draw1PCountdownDigitTileSlots` at `01:$42F5`. |

Notes:

- The pointer table starts at `01:$40A0`.
- Some pointers intentionally point back into the table area, for example `01:$40AE`; this is preserved by placing labels inside the table.
- `docs/source_recovery/sprite_oam.md` records the recovered format: `SpriteUpdatePointerTable` maps object types to frame tables with `SPRITE_OBJECT_FRAME_TABLE`, each frame entry is emitted as `SPRITE_FRAME_RECORD tile_id_list, layout_list`, tile-id lists use `SPRITE_TILE_LIST_N`, and layout lists contain repeated `SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr` triples terminated by `SPRITE_LAYOUT_ATTR_END`.
- Object type `$06` is now identified as `SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT`, the timed slot `10 + FALLING_PIECE_GRID_COLUMN` effect created by `SpawnFieldColumnEffect`; object type `$07` is now `SPRITE_OBJECT_TYPE_RESERVED_7` because the frame-table entry exists but no producer is confirmed.
- Earlier compatibility `DEF` symbols for fake sprite-data labels were removed after the downstream music streams were converted and no longer referenced them.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 1 Gameplay Field Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$442C-$445B` | `FieldColumnTilePatternTable` | Converted to `FIELD_COLUMN_TILE_PATTERN_ROW` | `DrawFieldColumnTilePattern` shifts `FIELD_COLUMN_TILE_PATTERN_INDEX` left `FIELD_COLUMN_TILE_PATTERN_INDEX_SHIFT` times, indexes this base address through `GetArrayElement`, then copies one `FIELD_COLUMN_TILE_PATTERN_RECORD_SIZE` record to the BG/field destination. The next byte at `01:$445C` is a real code entry, now labeled `StartNextRound`. |

Notes:

- The range is three `FIELD_COLUMN_TILE_PATTERN_RECORD_SIZE` records expressed
  as six `FIELD_COLUMN_TILE_PATTERN_ROW` rows. Row entries use `BLANK`,
  `LEFT_MARKER`, and `RIGHT_MARKER` roles mapped to the field blank tile and
  the playfield bottom-column marker tiles.
- `StartNextRound` is called from two Bank 0 round-end paths and resets round/egg/transient state before resuming `GAME_STATE_PLAYING`.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 1 Tile Strings

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$45C6-$45EF` | `UnusedInlineEggTextFrame0Drawer` | Labeled unused code-shaped fragment | The live `DrawEggTextFrame0` wrapper jumps directly to `DrawEggTextFrameByIndex`; this fragment is between that wrapper and `DrawEggTextFrameByIndex`, writes egg-text tiles directly, and has no confirmed static entry. |
| `01:$462B-$465C` | `EggTextFrame0..2TileRows` | Converted to `EGG_TEXT_TILE_ROW_N` string rows | `DrawEggTextFrameByIndex` selects one of three `DE` bases and calls `DrawStringToGrid` four times; each block is four `DRAW_STRING_ROW_END`-terminated tile rows. |
| `01:$46ED-$46FE` | `TitleLabelTextPlayer`, `TitleLabelTextYoshi` | Converted to `TITLE_LABEL_TEXT_ROW` string rows | `DrawTitleLabels` loads each address into `DE` and calls `DrawStringToGrid` at row/column pairs `$0F06` and `$1006`; the row macro names the per-row prefix tile, separator tile, shared suffix tile base, and terminator before the real `ProcessTitleInput` code entry at `01:$46FF`. |

## Bank 0 Board Pattern Tables

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$0A4D-$0A94` | `GridPiecePatternTable` | Converted to `GRID_PIECE_PATTERN_ROW` records | `GetGridPiecePatternOffset` multiplies the payload code by eight, and `DrawGridPiece` copies each record as two direct four-tile rows with `CopyTilePatternRow4`. |
| `00:$0A95-$0B04` | `ColumnSpritePatternTable`, `UnreachedColumnSpritePatternTailRows` | Converted to `COLUMN_SPRITE_PATTERN_ROW` records | `GetColumnSpritePatternOffset` multiplies the column index by twelve for the live two-frame column-sprite blocks. The final 16-byte tail remains separated as unreachable by the confirmed four-column/two-frame path but now uses the same four-tile row shape. |

Bank 1 tile-string notes:

- The Bank 1 tile-string ranges were previously decoded as instruction-looking bytes because the disassembly did not know the `DrawStringToGrid` string contract.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 1 Sound Engine Code and Tables

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `01:$55E2-$5668` | `StartSoundSequence` | Converted from `db` to code | `SoundEngine` and `SoundLookupIndex` both jump to `$55E2`. The bytes form a coherent routine that expands the selected sound entry from `$7C2C` into the `$C006/$C016/$C026...` sound channel state arrays and returns at `$5668`. |
| `01:$5669` | `SoundWaveDutyData` | Converted to `SOUND_WAVE_DUTY_END` record | `StartSoundSequence` stores `$5669` into `$C012/$C013` for later sound processing; the single byte is the sequence-end command. |
| `01:$566A-$5671` | `SoundRegisterOffsetTable` | Converted to `SOUND_REGISTER_OFFSET_ENTRY` records | `SoundUpdate3` indexes this 8-byte table to compute an `rNRxx` HRAM register address. |
| `01:$5672-$5679` | `SoundChannelDisableMaskTable` | Converted to `SOUND_CHANNEL_MASK_ENTRY` records | `UpdateSoundChannelOutputMask` indexes this table while masking `rNR51`. |
| `01:$567A-$5681` | `SoundChannelEnableMaskTable` | Converted to `SOUND_CHANNEL_MASK_ENTRY` records | `UpdateSoundChannelOutputMask` indexes this table while enabling/mixing channels in `rNR51`. |
| `01:$5682-$5699` | `SoundPitchBaseTable` | Converted to `SOUND_PITCH_BASE_ENTRY` records | `SoundUpdate5` indexes this table as 12 16-bit pitch/frequency base values. The entries are now named `SOUND_PITCH_BASE_INDEX_0..11`, matching the low-nibble table index consumed by the note and pitch-slide paths. The following `$569A` byte is a real sequence entry target from `SoundIndexTable`, not part of the pitch table. |
| `01:$569A-$5FE2` | `TitleBgmChannel0Sequence`, `SoundSequenceData_569c` through `SoundSequenceData_5f30` | Labeled existing `db` with internal boundaries and named Title BGM entry channels | This range was already represented as `db`, but it was one large block and started two bytes too late. `$FD/$FE` pointer targets and sound-index targets now have labels. `SoundIndexEntry_TitleBgm` directly installs `TitleBgmChannel0Sequence`, `TitleBgmChannel1Sequence`, `TitleBgmChannel2Sequence`, and `TitleBgmChannel3Sequence` as the four top-level channel streams for `SND_TITLE_BGM`; `TitleBgmChannel1Sequence` now exposes its duty/length, vibrato, length/envelope, and octave setup command records, `TitleBgmChannel2Sequence` uses `SOUND_LENGTH_ENVELOPE` plus four `SOUND_SUBSEQUENCE_CALL SoundSequenceData_5a34` records, and `TitleBgmChannel3Sequence` / `SoundSequenceData_5a89` expose channel-3 length-scale, rest, nested-sound note, and loop records. Other internal sequence joins retain address-based labels until their command roles are decoded. |
| `01:$5FE3-$7190` | `MusicSequenceData_5fe3` through `MusicSequenceData_6f92` | Converted to `db` | `Yoshi/yoshi.sym` now marks `$5FE3` as `.data:11ae`. The range is a dense music-command stream with many `$FD/$FE` pointer targets and joins the existing music data at `$7191`; no real code references remain. |
| `01:$7191-$71C0` | `MusicSequenceData_7191` | Labeled existing `db` | `Yoshi/yoshi.sym` marks this exact range as `.data:30`; the current source already stored the bytes as `db`, so this step adds the missing boundary label. |
| `01:$71C1-$71E3` | `MusicSequenceData_71c1`, `MusicSequenceData_71c2`, `MusicSequenceData_71d5` | Converted to `db` | `Yoshi/yoshi.sym` now marks this short range as `.data:23`. It sits between confirmed music data blocks, contains `$FD/$FE` music pointers, and has no confirmed real code entry. |
| `01:$71E4-$77B5` | `MusicSequenceData_71e4` through `MusicSequenceData_779b` | Converted to `db` | This larger stream spans the earlier `MusicSequenceData_71e4`, the fake-code `$73B3` island, and the following instruction-looking bytes up to `$77B5`. It contains dense music command bytes and `$FD/$FE` internal pointers, with no confirmed real code entry inside the range. |
| `01:$77B6-$7805` | `MusicSequenceData_77b6`, `MusicSequenceData_77c5` | Converted to `db` | `Yoshi/yoshi.sym` now marks this exact range as `.data:50`. The apparent calls into `$77B6/$77C5` came from music-data bytes decoded as instructions. The range contains repeated sequence bytes and pointer-like operands consistent with the neighboring music stream. |
| `01:$7806-$7C01` | `MusicSequenceData_7806` through `MusicSequenceData_7be7` | Converted to `db` | `Yoshi/yoshi.sym` now marks this range as `.data:3fc`. It directly follows the recovered `$77B6-$7805` sequence block and contains music commands, local `$FD/$FE` pointer targets, repeated `$FF` terminators, and no real code references. The next six bytes at `$7C02-$7C07` are real code and are deliberately excluded. |
| `01:$7C2C-$7D84` | `SoundIndexTable`, `SoundIndexEntry_*` | Converted to `SOUND_INDEX_ENTRY` records | `SoundLookupIndex` and `StartSoundSequence` compute `index * 3 + $7C2C`; each `SOUND_INDEX_ENTRY` emits one flags/channel byte and one little-endian sequence pointer. |
| `01:$7D85-$7DBC` | `SoundSequenceData_7d85` through `SoundSequenceData_7db9` | Converted to `SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE` records | These short sequence entries are direct channel-7 targets of early `SoundIndexTable` entries. Each one emits one `$20` extended-note command, two channel-7 operands, and `SOUND_SEQUENCE_END_COMMAND`; the operand roles remain intentionally unnamed until the channel-7 hardware mapping is fully decoded. |
| `01:$7DBD-$7DCE` | `SoundWavePatternPointerTable` | Converted to `SOUND_WAVE_PATTERN_POINTER` records | `ProcessNote` indexes `$7DBD` with the wave selector and copies 16 bytes from the selected pointer to wave RAM. |
| `01:$7DCF-$7FF5` | `SoundWavePatternData_*`, `SoundSequenceData_*` | Dedicated patterns converted to paired `SOUND_WAVE_PATTERN_ROW` records; selected effect sequences converted to sound-command records | Contains three dedicated 16-byte wave patterns, a shared `$7DFF` wave/sequence entry, and the remaining sound-index sequence targets through `$7FF5`. `SoundSequenceData_7e15`, the channel-5 half of the pause sound pair, now uses generic duty/extended-note/end records. `SoundSequenceData_7e2c`, `7eb4`, and `7ec7` now use generic duty/extended-note/end records. `SoundSequenceData_7e67` through `7ea9` are the channel-4 board-scan step entries selected by `SoundIndexEntry_BoardScanStep0..6`; they share the same duty/sweep/note/envelope/frequency-high/final-sweep command layout and vary only the explicit frequency-low operand. The other short channel-4 sweep/extended-note effects at `7e4b`, `7e5c`, `7eda`, `7eeb`, `7ef6`, `7f29`, `7f34`, `7f43`, `7f52`, and `7f9d` now use `SOUND_DUTY_LENGTH`, `SOUND_SWEEP`, `SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END` records. The tail-adjacent entries `7f0d`, `7fb4`, `7fd0`, and `7fe3` also use duty/extended-note/end records; `7f0d` and `7fb4` deliberately fall through to the shared end-only labels at `7f1b` and `7fc2`. Channel-7 entries `7f1c` and `7fc3` use `SOUND_CHANNEL7_EXTENDED_NOTE` records because channel 7 consumes two operands after each `$20-$2F` command. `SoundSequenceData_7f65` and `7f80` now expose their gate flag, length/envelope, octave, and pitch-slide tail commands with generic sound-command records. |
| `01:$7FF6-$7FFF` | `Bank1TailPaddingData` | Converted to `REPT` padding words | After `SoundSequenceData_7fe3` ends at `01:$7FF5`, the last ten bytes are five repeated little-endian `$3900` padding words. The range has no sound-index label or executable reference and is now separated from the final sound sequence. |

Notes:

- Earlier notes treated all of `01:$55E2-$5FE2` as sound data. That was too broad: the entry at `$55E2` is executable code reached by real jumps.
- The sequence data beginning at `TitleBgmChannel0Sequence` is now explicit `db` with first-pass pointer-target and sound-index labels. The four direct Title BGM sound-index targets have channel-entry names. The direct `BgmOption0..2`, `BgmPreview0..2`, link-role, confirm, link-result, 1P result, 2P result, and 2P preplay-init top-level channel targets are also named by their sound-index groups. `BgmOption0*` through `BgmOption2*` and `BgmPreview0*` through `BgmPreview2*` channel heads now expose their setup/rest/visual-update records before falling through to the remaining raw music streams. The link-role channel heads and their short `$FD/$FE` call/loop records now expose the same generic command forms, with the `LinkSlaveChannel3Sequence` pointer split preserved at the existing `MusicSequenceData_71e4` boundary. The confirm channel heads now expose setup, pitch-slide, channel-3 nested-sound-note, rest, and end records; the link-result nonzero/zero channel heads now expose setup, rest, octave, and end records. The link-result confirm/menu wait loop streams now expose their setup plus `$FD/$FE` branch structure, their shared phrase labels now expose octave, rest-note, channel-3 nested-sound-note, loop, and end records, and their remaining inline phrases now expose octave/rest-note command records while retaining raw pitch bytes. Full command decoding and broader track naming still remain.
- `MusicSequenceData_60ce` through `MusicSequenceData_6158`, the BGM preview 0 channel-3 visual pulse loop labels, now expose visual-update, rest-note, channel-3 length-scale, and loop records while preserving the existing pointer-target labels and fall-through structure.
- `MusicSequenceData_64f0` through `MusicSequenceData_656e` and `MusicSequenceData_6b2a` through `MusicSequenceData_6c9b`, the BGM preview 1/2 channel-3 visual pulse loop labels, now follow the same generic command-record structure.
- `Result1PNoRankChannel*Sequence` and `Result1PRankedChannel*Sequence` now expose their setup/rest/sequence-end records with generic sound command macros while keeping pitch bytes raw.
- `Result2PNonzeroRankChannel*Sequence` and `Result2PZeroRankChannel*Sequence` now expose their setup/rest/pitch-slide/sequence-end records with generic sound command macros while keeping pitch bytes raw.
- The 2P preplay-init channel entry heads now use generic sound-command records for tempo, master volume, duty/length, length/envelope, rest, and frequency-carry toggle setup bytes. The following phrase labels now expose length/envelope, octave, and loop records while keeping pitch bytes raw.
- `MusicSequenceData_7bdf`, installed by `SoundIndexEntry_LinkFieldRise`, now exposes its gate-flag, duty/length, length/envelope, octave, extended-note, pitch-slide, and sequence-end records while keeping note bytes raw.
- `SoundWavePatternData_SharedSequence` and `SoundSequenceData_7dff` intentionally share the same address because the wave pointer table and sound index table both target `$7DFF`.
- Temporary compatibility `DEF` symbols for fake music-data references were removed after the referencing streams were converted to explicit data.
- `01:$7C02-$7C07` is not part of the music stream. Bank 0 calls it twice, and it is now labeled `TickBgmPreviewTimer`.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 0 Gameplay Tables

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$0421-$0440` | `PauseOverlayOamTemplate` | Converted to `OAM_TEMPLATE_ENTRY` records | `DrawPauseOverlay` copies `PAUSE_OVERLAY_OAM_TEMPLATE_SIZE` bytes from this range to `SHADOW_OAM`. The template contains eight four-byte hardware OAM entries for the pause overlay, now emitted as `OAM_TEMPLATE_ENTRY y, x, tile, attr` records using `PAUSE_OVERLAY_OAM_*` constants. |
| `00:$0B83-$0B8C` | `BTypeColumnTopRowSeedTable`, `GameTurnLevelStartIndexTable` | Converted to level-index entry records | B-type setup indexes the five `B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY` records by `ACTIVE_LEVEL` to choose the seeded top row. A-type game-turn setup indexes the five `GAME_TURN_LEVEL_START_INDEX_ENTRY` records to seed `GAME_TURN_TABLE_INDEX` in ten-record steps. |
| `00:$0B8D-$0ED4` | `GameTurnParamTable` | Labeled full table; converted fake-code head to `db`; full record body macro-structured | `InitGameTurnPieceDisplay` seeds `GAME_TURN_TABLE_INDEX` from `GameTurnLevelStartIndexTable`, and both it and `LoadGameTurnPieceDisplayStep` compute `GameTurnParamTable + index * 4` using `GAME_TURN_PARAM_RECORD_SHIFT`. The table has `GAME_TURN_PARAM_RECORD_COUNT` four-byte records: the first byte reloads `GAME_TURN_STEP_TIMER`, the second byte becomes `PIECE_DISPLAY_COUNT` and the count argument to `BuildPieceDisplayStatesForCount`, and the third reloads `GAME_TURN_DELAY`. The fourth byte is `$01` in every record, emitted by `GAME_TURN_PARAM` as `GAME_TURN_PARAM_UNREAD_TAIL_VALUE`; no reader of offset `GAME_TURN_PARAM_UNREAD_TAIL_OFFSET` has been confirmed. `Yoshi/yoshi.sym` marks the full `$348`-byte range from `00:$0B8D`; `GameTurnParamTableContinuation` is preserved at `00:$0C40` with `GAME_TURN_PARAM_SPLIT_HEAD` / `GAME_TURN_PARAM_SPLIT_TAIL` around the label. |
| `00:$117C-$119B` | `MatchingOamTemplateTop`, `MatchingOamTemplateMiddle`, `MatchingOamTemplateFinal` | Converted to `OAM_TEMPLATE_ENTRY` records | `ProcessMatching` copies the middle template to `$C408`; the later matching/result animation copies the top and final templates to `$C400`. Each record is standard four-byte OAM layout data, now emitted as `OAM_TEMPLATE_ENTRY y, x, tile, attr` records using `MATCHING_*_OAM_*` coordinate/initial-tile constants and `OAM_ATTR_NONE`. |
| `00:$119C-$11D3` | `MatchingScoreBonusTable` | Converted to `SCORE_DELTA_ENTRY` records | `ApplyMatchingScoreBonusAndWait` indexes this table with `STATE_TRANSITION << MATCHING_SCORE_BONUS_RECORD_SHIFT`, loads the first byte into `H` and second byte into `L`, then calls `AddScore`. The entries are emitted as big-endian packed-BCD `SCORE_DELTA_ENTRY` records using `MATCHING_SCORE_BONUS_DELTA_*` constants. |
| `00:$11D4-$11EF` | `MatchingTileBaseIndexTable` | Converted to `MATCHING_TILE_BASE_INDEX_ENTRY` records | `ProcessMatching` and the later matching/result animation index this 28-byte table with `STATE_TRANSITION`, then scale the value with `MATCHING_MIDDLE_OAM_TILE_INDEX_SHIFT` or `MATCHING_FINAL_OAM_TILE_INDEX_SHIFT` to choose result sprite tile IDs. The entries are now expressed as `MATCHING_TILE_BASE_INDEX_STATE_0..27`, matching the capped `MATCHING_STATE_COUNT` range. |
| `00:$15FE-$1611` | `LevelFallDelayTable` | Converted to `LEVEL_FALL_DELAY_ENTRY` records | `GetLevelFallDelay` loads this address, caps active level to `$13`, and calls `GetArrayElement`; the result seeds the fall timer at `$C6A7`, halved when `ACTIVE_SPEED` is nonzero. Entries are named `LEVEL_FALL_DELAY_INDEX_0..19` for the capped `PROGRESSION_LEVEL` index. |
| `00:$18CB-$18D1` | `BoardScanTransitionFrameLimitTable` | Converted to `BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY` records | `RunBoardScanRoundTransition` indexes this table with the pre-remap `SCREEN_STATE`, writes the selected transition frame limit back to `SCREEN_STATE`, and `SendRoundTransitionFrameLoop` sends frames from `ROUND_TRANSITION_FRAME_START` through that selected limit. The entries are now expressed with `BOARD_SCAN_TRANSITION_FRAME_LIMIT_1..4`. |
| `00:$18D2-$18E3` | `BoardScanRewardScoreDeltaTable` | Converted to `SCORE_DELTA_ENTRY` records | The board-scan reward tail indexes this table with `BOARD_SCAN_REWARD_INDEX * 2`, loads the first byte into `H` and second byte into `L`, then calls `AddScore`. The entries are emitted as big-endian packed-BCD `SCORE_DELTA_ENTRY` records using `BOARD_SCAN_REWARD_SCORE_DELTA_50`, `_100`, `_200`, and `_500`. `BuildPieceDisplayObjects` starts immediately after at `00:$18E4`. |
| `00:$3799-$37BC` | `RoundCompleteSummaryMessageVeryGood/Excellent/SuperPlayer` | Converted to `ROUND_COMPLETE_SUMMARY_MESSAGE_HALF` tile-string records | `ShowATypeRoundCompleteSummary` selects one 12-byte message by egg-count range and copies it to `ROUND_COMPLETE_SUMMARY_MESSAGE_TOP_LEFT`. Each message is emitted as two six-byte half records, and the strings decode through `RoundCompleteSummaryTextTileData` as `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`. |
| `00:$37BD-$37C3` | `RoundCompleteFinalTileTable` | Converted to `ROUND_COMPLETE_FINAL_TILE` records | The final `ShowRoundComplete` branch indexes this seven-byte table by `ANIM_FRAME` and fills the current 2x2 tilemap box with the selected `ROUND_COMPLETE_FINAL_TILE_INDEX_*` tile. |
| `00:$37C4-$37DF` | `RoundCompleteRevealThresholdTable` | Converted to `ROUND_COMPLETE_REVEAL_THRESHOLDS` records | `ShowRoundComplete` indexes this table with `ROUND_COMPLETE_REVEAL_THRESHOLD_RECORD_SHIFT` (`ANIM_FRAME * 4`), then compares `STATE_TRANSITION` against each record's 500/200/100/50-point thresholds to choose how many summary rectangles and bonus sprites to reveal. |
| `00:$22CC-$230E` | `FieldSideDeltaTable` | Converted to delta-pair data | `StepFieldAnimSlot11SideDelta` and `StepFieldAnimSlot10SideDelta` index this table with `FIELD_ANIM_SLOT_11_CURSOR` / `FIELD_ANIM_SLOT_10_CURSOR` to step object slots 11 and 10. Entries are two-byte X/Y `FIELD_ANIM_DELTA_PAIR` records using `FIELD_ANIM_DELTA_POSITIVE`, `FIELD_ANIM_DELTA_ZERO`, and `FIELD_ANIM_DELTA_NEGATIVE`, followed by `FIELD_ANIM_END_SENTINEL`. |
| `00:$230F-$234B` | `FieldRowDeltaTable` | Converted to delta-pair data | `StepFieldAnimSlot13RowDelta` and `StepFieldAnimSlot12RowDelta` index this table with `FIELD_ANIM_SLOT_13_CURSOR` / `FIELD_ANIM_SLOT_12_CURSOR`; its X/Y delta pairs use the same `FIELD_ANIM_DELTA_PAIR` macro, and the next byte at `00:$234C` is the restored `UpdateFieldTimers` code entry. |

Notes:

- `GameTurnParamTableContinuation` is only an internal exact-address landmark
  inside the same 4-byte stride table; the actual indexed base is
  `GameTurnParamTable` at `00:$0B8D`. Because the landmark falls one byte
  before a four-byte record boundary, the preceding record is intentionally
  split with `GAME_TURN_PARAM_SPLIT_HEAD` / `GAME_TURN_PARAM_SPLIT_TAIL` so the
  label address stays exact.
- `00:$11F0` is deliberately left as code and labeled `UnusedDrawVerticalTilePairUnlessFF`; no confirmed direct caller has been found, but the bytes form a coherent helper that skips `UNUSED_VERTICAL_TILE_PAIR_SKIP_VALUE` and otherwise draws a vertical two-tile pair from tile base `UNUSED_VERTICAL_TILE_PAIR_TILE_BASE + A * 2`. It is not part of the matching tables.
- `00:$1612` is not table data. It is a real code entry called by `UpdateFallingPieceMotionAndLanding`, now labeled `HandleMatchedLandingScanState`, and falls through to `CommitFallingPieceToBoard` at `00:$162A`.
- The previous disassembly decoded bytes across the `00:$15FE-$1611` table and the `00:$1612` code entry as one misleading instruction stream.
- The previous disassembly also decoded `00:$18CB-$18E3` as instructions after `FinishBoardScanNoTargetLanding`, even though both `$18CB` and `$18D2` have direct table references.
- The previous disassembly decoded `00:$22CC-$234B` as instructions, making real calls to `00:$234C` appear to target the middle of an instruction stream.
- The previous disassembly decoded `00:$3799-$37DF` as instructions between
  `RevealRoundComplete2x2Block` and `AddScoreAndAnimateManualOamPair`, even
  though the round-complete summary path directly loads
  `$3799/$37A5/$37B1/$37BD/$37C4` as tables.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 0 Graphics Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$3839-$3D38` | `RoundCompleteSummaryGraphicTileData` | Converted to paired `ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS` records | `BuildRoundCompleteSummaryScreen` loads `DE=$3839`, `HL=ROUND_COMPLETE_SUMMARY_GRAPHIC_TILES_VRAM_DEST`, `C=ROUND_COMPLETE_SUMMARY_GRAPHIC_TILES_COPY_BLOCKS`, then calls `VRAMCopySetup`, copying 80 16-byte tiles for the A-type round-complete summary. The source emits two 8-byte four-row records per tile to avoid RGBDS two-digit macro arguments while preserving raw `$Cxxx` scan cleanliness. |
| `00:$3D39-$3E48` | `RoundCompleteSummaryTextTileData` | Converted to `ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE` records | The same path loads `DE=$3D39`, `HL=ROUND_COMPLETE_SUMMARY_TEXT_TILES_VRAM_DEST`, `C=ROUND_COMPLETE_SUMMARY_TEXT_TILES_COPY_BLOCKS`, then calls `VRAMCopySetup`, copying 17 16-byte text tiles. The glyph records map the message tile IDs `$14-$24` to the letters used by `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`; Cxxx-shaped glyph rows are emitted as binary bitmap literals so they are not confused with WRAM addresses. |
| `00:$3E49-$3FFF` | `Bank0TailPaddingData` | Converted to `REPT` prefix plus `db` suffix | Remaining ROM0 tail is unreferenced padding-like data. The prefix is 204 repeated `$0039` words (`BANK0_TAIL_PADDING_PREFIX_WORDS`), followed by a 31-byte terminal run; converting it removes fake `jr_000_39*`/`jp $7cc3` code labels while preserving the exact bytes. |

Notes:

- The `00:$3839-$3FFF` conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.
- `RoundCompleteSummaryTextTileData` is identified from both rendered tile
  evidence and the message tile IDs loaded by `ShowATypeRoundCompleteSummary`.
  `RoundCompleteSummaryGraphicTileData` remains named at the screen/art-block
  level because its individual 2x2 reveal graphics are selected indirectly by
  tile IDs during the reveal sequence.

## Bank 2 Unloaded Tail Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `02:$73D0-$7FFF` | `Bank2UnusedTailTileData` | Labeled explicit unused tail data | `Yoshi/yoshi.sym` marks the range as `.data:c30`; all confirmed Bank 2 graphics copies end at `TwoPlayerSharedTiles` (`02:$71D0-$73CF`), and no current source reference targets `02:$73D0`. Rendered evidence is mostly noise/padding-like data rather than coherent UI or character tiles. |

Notes:

- This is a label refinement of an already-explicit data range; it does not
  move bytes or change the ROM layout.

## Bank 0 Option UI Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$1D84-$1DAE` | `OptionTextAGame` through `OptionTextOff` | Converted to `OPTION_TEXT_ROW_N` strings | `DrawOptionTextLabels` loads each address into `DE` and calls `DrawStringToGrid` at fixed row/column pairs `$0102`, `$010C`, `$0402`, `$0B02`, `$0F02`, `$0C09`, `$0C0F`, and `$1010`; the rows use `OPTION_TEXT_TILE_*` constants and decode as `A GAME`, `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, and `OFF`. |
| `00:$1DAF-$1DBE` | `OptionMarkerPositions` | Converted to `OPTION_MARKER_POSITION` records | `DrawOptionMarkers` iterates eight row/column pairs derived from `OPTION_MARKER_*_COORD`, calls `CalcTilemapAddress`, clears each marker tile to `OPTION_MARKER_BLANK_TILE`, then draws active game-type, speed, and BGM markers with `OPTION_MARKER_SELECTED_TILE`. |
| `00:$1E3D-$1E4F` | `OptionCursorInactiveTileTriplets` | Converted to `DRAW_TILE_TRIPLET` records | `DrawTileTripletList` consumes row/column/tile triples until `DRAW_TILE_TRIPLET_LIST_END`; `UpdateCursorDisplay` uses this list to draw inactive cursor tiles for the level, speed, and BGM rows. |
| `00:$1E75-$1E89` | `SettingsCursorSpriteInit0..2` | Converted to `SETTINGS_CURSOR_INIT_RECORD` records | `ApplySettings` copies three fixed `SETTINGS_CURSOR_INIT_COPY_SIZE` records to `$C290`, `$C2A0`, and `$C2B0`; the records initialize type, frame/toggled-frame, shared base Y, unused/grid-column byte, and base X. |
| `00:$1F4C-$1F4F` | `DetachedPreplayOptionCountTable` | Converted to `PREPLAY_OPTION_COUNT_ENTRY` records | Detached pre-play option increment code indexes this four-byte table with `MENU_CURSOR` before accepting a right-button change. |
| `00:$2026-$203A` | `OptionCursorLevelHighlightTileTriplets`, `OptionCursorSpeedHighlightTileTriplets`, `OptionCursorBgmHighlightTileTriplets` | Converted to `DRAW_TILE_TRIPLET` records | `DrawLevelCursorHighlight`, `DrawSpeedCursorHighlight`, and `DrawBgmCursorHighlight` pass these addresses to `DrawTileTripletList` to draw the highlighted cursor row with active cursor tiles. |
| `00:$254E-$254F` | `LinkSettingsOptionCountTable` | Converted to `LINK_SETTINGS_OPTION_COUNT_ENTRY` records | `Run2PPreplayLoop` indexes this two-byte table with `LINK_SETTINGS_CURSOR` before accepting a right-button change to 2P level or speed. |
| `00:$2B9D-$2BA0` | `ResultRecordPaletteSequence` | Converted to `RESULT_RECORD_PALETTE_FADE_STEP` records | `FadeInResultRecordPalette` reads four bytes from this table, writes each to `rBGP`, and calls `WaitVBlankFrames` with `C=$10` after each palette step. |
| `00:$2C60-$2C63` | `PreplayLoopOptionCountTable` | Converted to `PREPLAY_OPTION_COUNT_ENTRY` records | `Run1PPreplayLoop` uses the same four option-row limits before accepting an increment in the 1P pre-play/start-wait path. |

Notes:

- The old labels `UpdatePaletteFade`, `UpdateHighScore`, `LoadSettings`, and `SaveSettings` were misleading for this area. They are now named `DrawOptionTextLabels`, `DrawOptionMarkers`, `DrawOptionMarker`, and `DrawTileTripletList`.
- The old labels `SaveConfig1..3` and `DrawOptionItem` were also misleading
  option-UI names. They are now `DrawLevelCursorHighlight`,
  `DrawSpeedCursorHighlight`, `DrawBgmCursorHighlight`, and
  `ReturnFromDrawOptionGameTypeLabel`.
- The byte at `00:$203B` is still an explicit `ret` immediately before `DrawOptionValues`; it is not part of the three highlighted cursor triplet lists.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Bank 0 Score/Result Text Data

| Range | Source label | Status | Evidence |
|-------|--------------|--------|----------|
| `00:$25C3-$25E0` | `ScoreHeaderTextRole1`, `ScoreHeaderTextRoleOther` | Converted to `TWO_PLAYER_ROLE_HEADER_TEXT` strings | `Draw2PPreplayRoleHeader` selects one of the two `DRAW_STRING_ROW_END`-terminated strings based on `LINK_ROLE`, then calls `DrawStringToGrid`; the macro uses the existing two 4-tile role header rows plus the named `$D1/$D2` suffix tiles. |
| `00:$2622-$2663` | `ResultTextBlock0..2` | Converted to `PREPLAY_SPEED_TEXT_ROW` two-line strings | `Draw2PPreplaySpeedText` and `Draw1PPreplaySpeedText` select these blocks, then call `DrawStringToGrid` twice; each block contains two rows made from a four-tile left run, two panel-clear gap tiles, a four-tile right run, and `DRAW_STRING_ROW_END`. |
| `00:$2CBC-$2CD6` | `ResultHeaderText` | Converted to `PREPLAY_HEADER_TEXT_ROW_*` two-line string | `Draw1PPreplayHeaderText` draws the header through `DrawStringToGrid`; the text decodes as `1 PLAYER GAME` / `YOSSY EGGS`, with the long rows split into 8-tile starts and 5-/4-tile terminator fragments. |
| `00:$2DE0-$2E2D` | `RestartTextBlock0..2` | Converted to `PREPLAY_GAME_TYPE_TEXT_ROW_*` two-line strings | `Draw1PPreplayGameTypeText` selects one of three two-line blocks, then calls `DrawStringToGrid` twice. Each 12-tile row is emitted as a six-tile start plus a six-tile terminator fragment to avoid ambiguous long macro arguments. |
| `00:$2E38-$2E3B` | `ContinueOffText` | Converted to `OPTION_TEXT_ROW_3` duplicate `OFF` string | `Draw1PPreplayBgmOffText` draws this duplicate `OFF` row through `DrawStringToGrid`, using the same option text tile constants as `OptionTextOff`. |
| `00:$2E7C-$2EB2` | `BgmMarker0Text..BgmMarkerNoneText` | Converted to `PREPLAY_BGM_MARKER_*` strings | `Draw1PPreplayBgmMarker` selects one marker line by `OPTION_BGM`, or an all-space line while the off marker blinks. The row macros name the 10-tile width and the selected marker offsets for BGM options 0, 1, 2, and off. |
| `00:$2734-$2853` | `PiecePreviewTextTable`, `PiecePreviewText0..4`, `PiecePreviewBlankText` | Converted to `PIECE_PREVIEW_*_CELL` tile strings | `Draw2PPreplayLevelTextAtIndex` and `Draw1PPreplayLevelTextAtIndex` index this table with `a * 48`, then call `DrawStringToGrid` three times; each entry is three 16-byte `DRAW_STRING_ROW_END`-terminated rows made from five selected/unselected preview cells. |
| `00:$2FFB-$304A` | `CountdownDigitPatternTable`, `CountdownDigitPattern0..9` | Converted to `COUNTDOWN_DIGIT_PATTERN` records | `UpdateCountdownTimer` indexes this table after shifting BCD-like countdown nibbles; each record is the 8-byte bitmap source for one decimal digit, and the routine copies 7 visible rows. |

Notes:

- These blocks were all previously decoded as instructions because the disassembly did not know the `DrawStringToGrid` data contract.
- The conversion is behavior-preserving: after rebuilding, `Yoshi/game.gb` remains byte-identical to `Yoshi/yoshi.gb`.

## Remaining High-Value Data Cleanup

| Range | Reason |
|-------|--------|
| Bank 1 sound/music command semantics | The byte streams now have boundaries, but the command names, track grouping, and channel roles still need a dedicated format pass. |
| Other Bank 0 inline tables | Some unrelated rows still show instruction-looking bytes that may be data. Convert only after exact call/index boundaries are confirmed. |
