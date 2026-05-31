# Findings & Decisions

## Requirements
- Recover the lost Game Boy YOSSY NO TAMAGO source from the existing ROM/disassembly.
- Preserve behavior and use the current ROM as ground truth.
- Improve labels, comments, memory maps, bank structure, and data/code separation.
- Prefer evidence-backed recovery over speculative rewriting.
- Aim for the best attainable source reconstruction, accepting a long-running iterative process.

## Known Facts
- ROM path: `Yoshi/yoshi.gb`
- Built/rebuilt path also present: `Yoshi/game.gb`
- Both are 65,536 bytes.
- Header title is `YOSSY NO TAMAGO` at `0x0134`.
- `Yoshi/yoshi.sym` now includes the recovered reset vector labels
  `RST_00` through `RST_38`, the five interrupt-vector labels, and the
  cartridge header labels from `HeaderLogo` through `HeaderGlobalChecksum`.
  The symbol file marks `00:$0000-$0067` as code and `00:$0104-$014F` as
  header data, matching the source and rebuilt `Yoshi/game.sym`.
- Cartridge type is `0x01` = MBC1.
- ROM size code is `0x01` = 64KB.
- RAM size code is `0x00` = no external RAM.
- Cartridge header metadata bytes are now represented by `HEADER_*`
  constants in `Yoshi/constants.inc`; `HeaderLogo` emits RGBDS's built-in
  `NINTENDO_LOGO` macro, and the fixed title bytes remain literal in
  `HeaderTitle`.
- Bank layout:
  - Bank 0: fixed `ROM0[$0000-$3FFF]`
  - Bank 1: switch window `ROMX[$4000-$7FFF], BANK[$1]`
  - Bank 2: switch window graphics data, `BANK[$2]`
  - Bank 3: switch window graphics data, `BANK[$3]`
- Runtime pattern observed:
  - Bank 1 is the normal active switch bank.
  - Bank 2/3 are selected temporarily for graphics copies, then Bank 1 is restored.
  - VBlank handler lives in Bank 1 at `$4B59`, so Bank 1 must be active during normal LCD-on execution.

## User Testimony
- User programmed the GB version with Yuji Shinkai.
- Original source is lost.
- GB version was allowed to use 64KB by Nintendo to shorten development.
- FC version was created later in about five weeks.

## Research Findings
- `Yoshi/bank_000.asm` contains bank switch writes to `$2100`.
- Examples:
  - Title initialization switches to Bank 2, copies graphics to VRAM, then restores Bank 1.
  - Game initialization switches to Bank 2 for game tiles, then restores Bank 1.
  - Several transition/result paths switch to Bank 3 for graphics, then restore Bank 1.
- `Yoshi/yoshi.sym` already contains high-level bank annotations and many labels.
- `Yoshi/ARCHITECTURE.md` contains an existing architecture summary that should be validated rather than blindly trusted.
- Simple ASCII searches found no visible `AKIHITO`, `koriyama`, or Game Freak credit strings in `Yoshi/yoshi.gb` or `Yoshi/game.gb`.
- `make -B` in `Yoshi/` rebuilds `Yoshi/game.gb` byte-for-byte identical to `Yoshi/yoshi.gb`.
- `Yoshi/yoshi.gb` and rebuilt `Yoshi/game.gb` both have SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
- The VRAM copy HRAM block is now evidence-aligned:
  - `$FFAE` = `VRAM_COPY_BLOCKS`, a 16-byte block count used by `VRAMCopyDMA`.
  - `$FFAF/$FFB0` = source pointer low/high.
  - `$FFB1/$FFB2` = destination pointer low/high.
  - `$FFB3-$FFB7` = `UNUSED_VRAM_COPY2_*`, written only by an unreachable secondary-copy setup fragment at `00:$0244`; the live VBlank DMA path does not read it.
- Bank 1 VBlank/VRAM locals now name the queued 16-byte VRAM copy loop, VBlank
  sync/busy branches, wave-update continuation, VBlank return tail, and
  `WaitVBlankSyncLoop`.
- The executable Bank 1 wait loops now expose their raw `$76` bytes as `halt`
  instructions in `WaitVBlankSyncLoop` and `WaitJoypadStartOrSelectPressLoop`.
- `WaitVBlank` now stores `VBLANK_SYNC_REQUESTED` before halting until VBlank
  clears the sync byte. The static-dead Bank 1 helper at `01:$4BD0` is now
  labeled `UnusedWaitSelectThenStartOrSelectPress`; it checks `PADF_SELECT`,
  then waits for `PADF_START_OR_SELECT` while restoring the saved joypad bytes
  with `PADF_SELECT_CLEAR_MASK`.
- `tools/recovery_refs.py` provides a repeatable WRAM/HRAM reference summary for `bank_000.asm` and `bank_001.asm`.
- The high-frequency reference scan highlights fake code references inside sound/music data. The previous assumption that all of `01:$55E2-$5FE2` was data was too broad: `$55E2-$5668` is executable sound setup code, while later ranges still need sequence/data boundary recovery.
- `GAME_STATE` (`$FFC7`) has seven observed values, now defined in `Yoshi/constants.inc`:
  - `$00` title init
  - `$01` title menu
  - `$02` play setup
  - `$03` playing
  - `$04` round end/result/high-score
  - `$05` pre-play settings/start-wait loop
  - `$06` pre-play one-shot init
- `docs/source_recovery/state_machine.md` records the current state meanings and observed transitions.
- The old `PLAYER_MODE` name at `$C671` was misleading. Evidence shows `$C671` is an active A/B-style game type, while 1P/2P is controlled by `TWO_PLAYER_FLAG` at `$C6B6`; it is now named `GAME_TYPE`, with `GAME_TYPE_A` (`0`) and `GAME_TYPE_B` (`1`) constants.
- The settings bytes `$C6B2-$C6B5` are now named `OPTION_GAME_TYPE`, `OPTION_LEVEL`, `OPTION_SPEED`, and `OPTION_BGM`.
- The active gameplay copies `$C6B7-$C6B8` are now named `ACTIVE_LEVEL` and `ACTIVE_SPEED`.
- `docs/source_recovery/options_variables.md` records the current evidence for these settings variables.
- Bank 1 range `01:$40A0-$42F4` is sprite update data, not executable code. It is now represented as `SpriteUpdatePointerTable`, `SpriteFrameTable_*`, `SpriteTileList_*`, and `SpriteLayout_*` labels, with object-pointer, frame, tile-list, and layout macros for the four recovered record shapes.
- `UpdateSprites` expands 16 logical sprite object slots at `$C200-$C2FF` into the `$C400-$C49F` shadow OAM buffer.
- Bank 1 `UpdateSprites` now has local labels for its OAM expansion loop:
  `ScanSpriteObjectSlotLoop`, `DrawSpriteObjectOamEntryLoop`,
  `StoreSpriteObjectOamAttributes`, `AdvanceSpriteObjectSlot`, and
  `HideUnusedShadowOamLoop`.
- `UpdateSprites` now uses explicit redraw/frame sentinels:
  `LCD_REDRAW_HIDE_ALL_SENTINEL` for the hide-all path and
  `SPRITE_OBJECT_FRAME_DISABLED` for skipping a logical sprite object slot's
  frame. Title/playfield setup, unpause, and game-tile reload paths now store
  `LCD_REDRAW_EXPAND_REQUEST` explicitly before the next sprite expansion pass.
- Confirmed object type names now cover player cursor (`$01`), game-over piece (`$02`), round transition (`$03`), round-complete tile (`$04`), and settings cursor (`$05`).
- Object type `$06` is now `SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT`. `SpawnFieldColumnEffect` creates it in logical sprite slot `10 + FALLING_PIECE_GRID_COLUMN`, sets frame/base Y/base X from the current column/fall position, and reloads the matching `FIELD_COLUMN_TIMERS` entry before `UpdateFieldTimers` later clears the slot.
- Sprite slot byte `+$03` is now narrowly documented as the option BGM cursor toggled-frame shadow: `ApplySoundVisualUpdateCommand` toggles it with `BGM_CURSOR_FRAME_TOGGLE_MASK` and copies it into `+$02` only when the BGM row is selected.
- Sprite slot byte `+$0F` is now `SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE`, but remains low confidence: the current static trace still finds only `HandlePlayfieldInput` clamping slots 1-4 to `PIECE_FAST_FALL_TIMER_CLAMP` while Down is held, with no independent initializer or consumer.
- Sprite slot byte `+$01` remains unused/padding in the current trace. `UpdateSprites` skips it, and no independent consumer has been confirmed.
- Sprite object type `$07` is now `SPRITE_OBJECT_TYPE_RESERVED_7`. The frame-table entry exists and draws two tile `$E0` sprites, but current source search finds no producer that writes `$07` as a logical sprite object type.
- High-bit logical sprite object values `$81-$87` are renderer-supported
  attribute variants rather than alternate frame-table entries. `UpdateSprites`
  saves bit `$80` in `SPRITE_OBJECT_ATTR_TMP`; then `dec` + `sla` drops bit 7
  from the frame-table offset, so `$81-$87` share the `$01-$07` tables while
  layout entries with `SPRITE_ATTR_INHERIT_BIT` can OR `$80` into OAM
  attributes. The current producer search only found LCD, sound, and link
  bit-7 operations outside the sprite type byte; no high-bit sprite object type
  writer is confirmed.
- `BOARD_COLUMN_BOTTOM_VISIBLE_CELL` is now identified as `BOARD_DATA + $0D`. `FillInitialBoardColumns` fills initial board pieces upward from this address by two bytes per row, and `AnimateDropping` uses the same bottom visible-cell base plus a 16-byte column stride.
- `BOARD_CELL_VISIBLE_PAYLOAD_OFFSET` now names the odd byte lane inside each
  two-byte board row cell. `DrawAllColumns` starts at `BOARD_DATA + $01`,
  advances by `BOARD_CELL_STRIDE`, and passes that byte to `DrawGridPiece`.
  `BOARD_ADJACENT_VISIBLE_CELL_DELTA` now names the same two-byte step when
  landing, initial-fill duplicate avoidance, and target scanning move to the
  next visible cell in a column.
  The paired even byte is now `BOARD_CELL_UNREAD_PAIR_OFFSET`: the current live
  source only clears it as part of `ClearBoardData`, and no live piece/display
  or scan consumer has been confirmed.
- `SHADOW_OAM_MANUAL_PAIR` is now identified at `$C498`, the two-entry tail beyond the `$98` automatic hide limit used by `AddScoreAndAnimateManualOamPair` for the direct round-complete bonus OAM animation.
- `BG_MAP_SHADOW_COPY_ENABLE_FLAG` (`$FFA5`) gates the VBlank-side
  `CopyNextBgMapShadowSlice` path. `BG_MAP_COPY_PHASE` (`$FFA6`) rotates that
  copy through the three six-row BG map shadow slices: `$C4A0->$9C00`,
  `$C518->$9CC0`, and `$C590->$9D80`. The three phase values are now named
  `BG_MAP_COPY_PHASE_SLICE_0..2`. `$FFA7/$FFA8` are now
  `VBLANK_SAVED_SP_HI/LO`, the scratch SP save used by both pop-based VBlank
  copy loops.
- Bank 1 `CopyNextBgMapShadowSlice` local labels now name the three-phase BG map copy
  path: `SelectBgMapShadowCopySlice0`, `SelectBgMapShadowCopySlice1`,
  `StoreNextBgMapShadowCopyPhase`, `CopyBgMapShadowSliceRowLoop`, and
  `CountBgMapShadowCopySliceRow`.
- The 2P result mark tilemap origins are now identified. `UpdateLinkResultMarksAndScreen` first clears six 2x2 mark boxes with tile `$14`, then draws filled `$10` boxes from `LINK_RESULT_NONZERO_MARK_BASE` (`$C4F3`) rightward and from `LINK_RESULT_ZERO_MARK_BASE` (`$C4FF`) leftward according to `LINK_RESULT_NONZERO_MARKS` / `LINK_RESULT_ZERO_MARKS`.
- Additional 2P result screen BG-map origins are now identified. `UpdateLinkResultMarksAndScreen` fills left/right header blocks at `$C4CD/$C4D3`, left/right 2x2 badge boxes at `$C4B7/$C4C3`, outcome blocks at `$C572/$C574`, and the row-15 status/text strip at `$C5D0/$C5D7`; `LINK_ROLE` and `ANIM_FRAME` select which tile-base pairs are drawn, so the source names describe layout positions rather than assigning player semantics.
- The remaining high-confidence matching/link result BG-map origins are now named. `ProcessMatching` uses `$C4ED` as a 3x3 intro blink block, `$C59B` as a three-tile animation strip while the matching OAM pair moves, and `$C4CA` as the final 2x16 result header. Link result confirmation uses `$C543` as the 6x6 wait panel and `$C571` as a 4x3 non-master detail block.
- `ProcessMatching` local labels now describe the visible transition sequence:
  clamping/storing the matching state, filling middle OAM tile IDs, running the
  intro scroll/blink loop, running the result-panel scroll/blink loop, sliding
  the top OAM pair right, sliding the middle/top OAM groups left, filling the
  result panel right edge, loading final OAM tile IDs, and moving the final OAM
  pair upward.
- `ProcessMatching` setup constants now capture the clamped state table length
  (`MATCHING_STATE_COUNT` / `MATCHING_LAST_STATE`), the 18-row BG map VRAM
  clear (`MATCHING_BG_VRAM_CLEAR_SIZE`), the matching blank/clear tile
  (`MATCHING_BG_CLEAR_TILE`), the LCDC mode used for the matching/result
  animation (`MATCHING_LCDC_FLAGS`), and the 4-entry middle / 2-entry pair OAM
  template sizes. The three matching OAM templates now also name their observed
  Y/X coordinates, initial tile IDs, and `OAM_ATTR_NONE` attribute bytes through
  `OAM_TEMPLATE_ENTRY y, x, tile, attr` records.
- `ProcessMatching` animation timing constants now capture the intro scroll
  start/count, intro blink period/split, post-intro wait, result-panel scroll
  start/count, result-panel blink period/split, panel fill tile stages, panel
  step waits, OAM slide frame count and signed X steps, final OAM tile base,
  final upward movement length, and the wait before applying the matching score
  bonus.
- The `ProcessMatching` animation sound IDs are now named from their direct
  call sites: `SND_MATCHING_INTRO_BLINK` fires when the intro blink counter
  wraps, `SND_MATCHING_RESULT_PANEL_BLINK` fires when the result-panel blink
  counter wraps, and `SND_MATCHING_OAM_SLIDE` fires immediately before the
  matching OAM slide starts.
- The matching score/result tail now names `ApplyMatchingScoreBonusAndWait`,
  which indexes `MatchingScoreBonusTable` by `STATE_TRANSITION <<
  MATCHING_SCORE_BONUS_RECORD_SHIFT`, applies the named packed-BCD
  `MATCHING_SCORE_BONUS_DELTA_*` score bonus, redraws the result stats, waits
  for the active sound to end, and then waits for button input before reloading
  the game tiles.
  `DrawResultScoreDigitsLoop` renders the five low-nibble `SCORE_DIGITS` to
  `RESULT_SCORE_VALUE_TOP_LEFT`.
- `DrawMatchingResultStats` now names the result-screen routine that draws the
  matching score, level, speed, and elapsed-time values. Its constants name the
  result score/level/time label tile bases, the shared one-row four-tile label
  rectangle, the three-tile time-label rectangle, the low-nibble digit mask and
  `$D4` digit tile base, the speed tile base, the time separator tile, and the
  `MATCHING_SCORE_LCDC_FLAGS` used before returning from the matching score
  display.
- The old `FillRectAlt` helper is now `WaitAnyButtonPress`. It polls
  `ReadJoypad` until `JOYPAD_PRESSED & PADF_ANY_BUTTON` is nonzero, so it waits
  for A/B/Select/Start and intentionally ignores the D-pad. It is used after the
  matching score display and by the result-record screen path when there is no
  blinking inserted-record label. The blinking result-record path now uses the
  same `PADF_ANY_BUTTON` mask in `PollResultRecordBlinkInput`.
- `$FF9D/$FF9E` are now `SCY_SHADOW` and `WY_SHADOW`. Startup initializes them, and Bank 1 VBlank copies them directly to `rSCY` / `rWY` next to the existing `SCX_SHADOW` path.
- Bank 1 wave-pattern loading now uses the existing hardware constant `_AUD3WAVERAM` for `$FF30-$FF3F`; the routine disables NR30, writes the selected 16-byte pattern, then re-enables the wave channel.
- Countdown digit buffer blit destinations are now named: `COUNTDOWN_BLIT_DEST_PHASE0` (`$9020`) receives buffers 2/3, and `COUNTDOWN_BLIT_DEST_PHASE1` (`$9120`) receives buffers 0/1.
- Common graphics-copy destinations now use project VRAM constants: `VRAM_TILE_BLOCK_8000`, `VRAM_TILE_BLOCK_8800`, `VRAM_TILE_BLOCK_9000`, plus specific 2P/high-score/title-result destination constants.
- Matching/result OAM animation now uses `SHADOW_OAM_ENTRY_*` and `OAM_*_OFFSET` constants for the direct template copies and per-entry X/tile adjustments around `$C400-$C40B`.
- The four round-complete tilemap boxes are now named `ROUND_COMPLETE_TILEMAP_ORIGIN_0..3` (`$C5B9/$C5BD/$C5C1/$C5C5`). They are prepared as 2x2 boxes, revealed one at a time by `ShowRoundComplete`, then paired with sprite groups at base X `$10/$30/$50/$70`.
- The A-type round-complete summary layout and data island are now identified. `ShowATypeRoundCompleteSummary` clears a 16x16 `BG_MAP_SHADOW` region, draws the header/panel/message origins at `$C4B4/$C544/$C56A`, copies one of three 12-byte messages from `00:$3799/$37A5/$37B1`, and `ShowRoundComplete` uses `RoundCompleteFinalTileTable` (`00:$37BD`) plus `RoundCompleteRevealThresholdTable` (`00:$37C4`) for the reveal sequence. The three summary strings now use paired `ROUND_COMPLETE_SUMMARY_MESSAGE_HALF` records and decode through `RoundCompleteSummaryTextTileData` as `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`; the 17 ROM0 text tiles now use `ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE` records keyed by the same tile ID constants, with Cxxx-shaped bitmap rows written as binary literals. The final tile table is now seven `ROUND_COMPLETE_FINAL_TILE` records using `ROUND_COMPLETE_FINAL_TILE_INDEX_0..6`, and the reveal table is seven `ROUND_COMPLETE_REVEAL_THRESHOLDS` records ordered as 500/200/100/50-point thresholds. The previous disassembly treated `00:$3799-$37DF` as code between `RevealRoundComplete2x2Block` and `AddScoreAndAnimateManualOamPair`.
- The round-complete reveal helpers are now named by behavior and constants:
  `RevealRoundComplete2x2Block`, `RevealRoundComplete3x2Block`, and
  `RevealRoundComplete3x4Block` fill the staged summary rectangles using the
  `ROUND_COMPLETE_REVEAL_*` tile/rect/offset constants and wait
  `ROUND_COMPLETE_REVEAL_BLOCK_WAIT_FRAMES`; `AddScoreAndAnimateManualOamPair`
  adds the corresponding bonus score, stages two manual OAM entries, moves them
  upward for `ROUND_COMPLETE_BONUS_ANIM_FRAMES`, then waits
  `ROUND_COMPLETE_BONUS_HOLD_FRAMES`.
- A-type round-complete bonus scoring now has explicit constants for the
  500/200/100/50 packed-BCD score deltas, the left bonus tile and OAM Y for
  each reveal branch, the shared right tile, the right-tile X step, and the
  manual-OAM animation/hold frame counts.
- The result record display rows are now named. `RESULT_RECORD_LABEL_ORIGIN_0..2` (`$C52D/$C555/$C57D`) are 3-tile row labels that blink in `WaitResultRecordScreenInput`; `RESULT_RECORD_LABEL_BLINK_ALT_START_FRAME` / `RESULT_RECORD_LABEL_BLINK_PERIOD` name the selected/normal label timing. `FillResultRecordPlaceholderColumn` seeds placeholder tiles at `$C534/$C538/$C53D` down all three record rows before `DrawStoredResultRecords` renders stored records from `RESULT_RECORD_VALUE_TOP_LEFT` (`$C530`). The rendering pass now names the five score digits, two level digits, A-type three-detail digits, B-type two-digit timer pairs, and the post-row delta `RESULT_RECORD_NEXT_RENDER_ROW_DELTA`.
- The result record screen setup layout is now named. It builds the header/type label/frame/header/detail blocks from `RESULT_RECORD_SCREEN_HEADER_TOP_LEFT` (`$C4B5`), `RESULT_RECORD_TYPE_LABEL_TOP_LEFT` (`$C4F7`), `RESULT_RECORD_BOX_TOP_LEFT` (`$C504`), `RESULT_RECORD_COLUMN_HEADER_TOP_LEFT` (`$C51D`), and A/B-specific detail origins at `$C527/$C5A6/$C5B0/$C5DA`; the row helper is now `FillResultRecordBoxRow`.
- The title UI BG-map rectangle origins and fill tile bases are now identified. `InitTitleUI` fills fixed frame/panel rectangles at `$C4B1`, `$C4B5`, `$C4C5`, `$C507`, `$C510`, and `$C575` with `TITLE_FRAME_TOP_RIGHT_CAP_TILE_BASE`, `TITLE_FRAME_INNER_TILE_BASE`, `TITLE_FRAME_RIGHT_STRIP_TILE_BASE`, `TITLE_MENU_PANEL_TILE_BASE`, `TITLE_LEVEL_STRIP_TILE_BASE`, and `TITLE_BOTTOM_RIGHT_PANEL_TILE_BASE`; names are limited to the title setup context because some addresses are shared by other screens.
- The 2P field occupancy count path is now identified. `QueueLinkFieldOccupancyCount` scans 7x4 sampled tiles from `FIELD_OCCUPANCY_SCAN_TOP_LEFT` (`$C4C8`), ignores empty tile `$4A`, draws the local count at `$C565-$C566`, and queues `count | $20`; incoming bit-5 packets dispatch to `ProcessLinkFieldCountPacket`, which draws the peer count at `$C5DD-$C5DE`.
- The 2P field occupancy sampler and digit renderer now have local loop names:
  `ScanLinkFieldOccupancyRow`, `ScanLinkFieldOccupancyColumn`,
  `AdvanceLinkFieldOccupancyColumn`, `CountLinkFieldTensDigitLoop`, and
  `StoreTwoDigitLinkFieldCount`.
- `FIELD_OCCUPANCY_COUNT_DECIMAL_BASE` now names the `$0A` divisor/subtractor
  used by `DrawTwoDigitLinkFieldCount` while converting the local or peer
  field occupancy count into tens/ones tile digits.
- The 2P link packet handlers are now named by packet role. `ProcessLinkFieldRisePacket` accumulates bit-6 payloads into `LINK_PENDING_FIELD_RISE`, `ProcessLinkResultPacket` handles bit-7 result packets during normal link ticks, and `QueueLinkResultPacketOutcome` is the decoded result-code merge before `QueueRoundResult`. `Exchange2PResultCode` sends the local result code with bit 7 set until it receives and stores the peer result code. The pending field-rise consumer now names its none value as `LINK_PENDING_FIELD_RISE_NONE`, its sound ID as `SND_LINK_FIELD_RISE`, and its screen-state cap as `LINK_FIELD_RISE_SCREEN_STATE_LIMIT`.
- The link packet dispatcher branch labels now distinguish packet detection from packet handling: `DispatchReceivedLinkFieldCountPacket` and `DispatchReceivedLinkFieldRisePacket` test the bit-5 and bit-6 packet classes before jumping to `ProcessLinkFieldCountPacket` / `ProcessLinkFieldRisePacket`.
- Bank 1 tile string ranges `01:$462B-$465C` and `01:$46ED-$46FE` are data, not code. `DrawEggTextFrameByIndex` and `DrawTitleLabels` pass these `DRAW_STRING_ROW_END`-terminated rows to `DrawStringToGrid`.
- `DrawStringToGrid` now names its row terminator as `DRAW_STRING_ROW_END`,
  matching the converted option, preplay, title, and egg-text tile-string data.
- The 1P option label strings `OptionTextAGame` through `OptionTextOff` now use
  `OPTION_TEXT_ROW_N` records with `OPTION_TEXT_TILE_*` constants for `A GAME`,
  `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, and `OFF`.
- The Bank 1 egg-text and title-label rows now use `DRAW_STRING_ROW_END` at
  their row ends as well. The three egg-text frame blocks now use
  `EGG_TEXT_TILE_ROW_2`, `EGG_TEXT_TILE_ROW_3`, and `EGG_TEXT_TILE_ROW_4`
  macros, with frame tile-base constants and `EGG_TEXT_ROW_FILL_TILE` for the
  side-panel fill tile. The title labels now use `TITLE_LABEL_TEXT_ROW`, with
  separate player/Yoshi prefix tiles and a shared separator/suffix tile run.
- The 1P preplay header text and duplicate `OFF` text now also use
  `DRAW_STRING_ROW_END` at their row ends.
- The 1P preplay header text `ResultHeaderText` now uses
  `PREPLAY_HEADER_TEXT_ROW_*` records and the option text tile alphabet plus
  `PREPLAY_HEADER_TEXT_TILE_1` for `1 PLAYER GAME` / `YOSSY EGGS`.
- The duplicate 1P preplay BGM `OFF` text now reuses
  `OPTION_TEXT_ROW_3 OPTION_TEXT_TILE_O/F/F`.
- The remaining Bank 0 preplay role header, speed/result, game-type, and BGM
  marker strings now use `DRAW_STRING_ROW_END` for the same
  `DrawStringToGrid` row-ending contract. The 1P game-type text blocks
  `RestartTextBlock0..2` now use paired `PREPLAY_GAME_TYPE_TEXT_ROW_START` /
  `PREPLAY_GAME_TYPE_TEXT_ROW_END` records for their 12-tile rows.
- The 2P preplay role header strings `ScoreHeaderTextRole1` and
  `ScoreHeaderTextRoleOther` now use `TWO_PLAYER_ROLE_HEADER_TEXT`, reusing the
  two existing 4-tile role header row constants and named suffix tiles.
- The Bank 0 preplay speed text blocks `ResultTextBlock0..2` now use
  `PREPLAY_SPEED_TEXT_ROW`, matching the observed row format: four left tiles,
  two panel-clear gap tiles, four right tiles, then `DRAW_STRING_ROW_END`.
- The BGM marker strings `BgmMarker0Text..BgmMarkerNoneText` now use
  `PREPLAY_BGM_MARKER_TEXT` / `PREPLAY_BGM_MARKER_NONE_TEXT` with a named
  10-tile width and selected-marker offsets for BGM options 0, 1, 2, and off.
- The 2P/1P level preview tile strings in `PiecePreviewText0..4` and
  `PiecePreviewBlankText` now use `DRAW_STRING_ROW_END` for each of their
  three fixed-width rows. The same table is now structured as selected and
  unselected `PIECE_PREVIEW_*_CELL` records with named level digit tiles.
- Bank 1 `01:$45C6-$45EF` is now labeled
  `UnusedInlineEggTextFrame0Drawer`. It is a coherent inline egg-text tile
  writer, but the live `DrawEggTextFrame0` wrapper jumps over it to
  `DrawEggTextFrameByIndex`, and no static entry reaches the fragment.
- `UnusedInlineEggTextFrame0Drawer` now uses `EGG_TEXT_FRAME0_TILE_BASE` and
  inline row-delta constants instead of raw `$F0-$FA` tile IDs and
  `$0013/$0012` row advances. The live `EggTextFrame0TileRows` table and the
  shared frame-2 `$F0-$F4` rows use the same tile-base expression.
- `$C6BC` and `$C6BE` are now named `TITLE_PLAYER_MARKER_TIMER` and `TITLE_PLAYER_MARKER_PHASE`; together they drive the title 1P/2P selection marker blink handled by `TickTitlePlayerMarkerBlink`. The adjacent write-only `$C6BD` byte now uses `TITLE_PLAYER_MARKER_UNUSED_DELAY_INITIAL`, and the sole Yoshi-side `$FF94` write is named `TITLE_RESET_UNUSED_HRAM_FLAG`.
- Bank 1 title marker helpers now use behavior names:
  `DrawTitlePlayerSelectionMarker`, `DrawTitleTwoPlayerSelectionMarker`,
  `TickTitlePlayerMarkerBlink`, `DrawTitlePlayerMarkerTop`, and
  `DrawTitlePlayerMarkerBottom`. The title input/link branch labels now name the
  1P/2P selection changes and pre-play transition path.
- Title input now uses hardware button constants for Up/Down/Select, named
  title-player mode bounds/toggle values, explicit label-row marker coordinates
  at `$0F05/$1005`, and `TITLE_LINK_START_BYTE` / `TITLE_LINK_READY_BYTE` for
  the two-byte link handshake that chooses slave/master roles. The 1P-select
  path now names the post-decrement `$FF` rejection value as
  `TITLE_PLAYER_MODE_UNDERFLOW_SENTINEL`.
- The recovered sprite update format is:
  - object slot `+$00`: active object type; zero skips the slot.
  - object slot `+$02`: frame index; `$FF` skips the slot.
  - object slot `+$04/+$06`: base Y/X, with hardware OAM biases `$10/$08`.
  - object pointer table entry: `SPRITE_OBJECT_FRAME_TABLE object_type, frame_table`.
  - frame table entry: `SPRITE_FRAME_RECORD tile_id_list, layout_list`.
  - tile-id list: `SPRITE_TILE_LIST_N` records, consumed one byte per emitted hardware sprite.
  - layout list: repeated `SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr`; `SPRITE_LAYOUT_ATTR_END` ends the list, and `SPRITE_LAYOUT_ATTR_INHERIT` requests the saved object `$80` attribute bit.
- `UpdateSpriteObject` is the first confirmed producer path for gameplay sprite objects: input `A=0..3` selects `$C210/$C220/$C230/$C240`, copies 10 bytes through `$C68C-$C695`, updates state, and writes the record back.
- Slot 0 (`$C200`) is a separately managed gameplay/cursor object initialized by `InitPlayerCursorObject`; slots 9-13 are reused by options, countdown, round-complete, and 2P field transition objects.
- `InitPlayerCursorObject` now names the slot-0 player cursor seed values:
  `FIELD_COLUMN_TILE_PATTERN_INITIAL_INDEX`, `PLAYER_CURSOR_INITIAL_FRAME`,
  `PLAYER_CURSOR_INITIAL_BASE_Y`, and `PLAYER_CURSOR_INITIAL_BASE_X`. The
  shared rectangle filler also uses `BG_MAP_ROW_STRIDE` for its row advance.
- `ClearSpriteObjectBuffer` now names the Bank 1 setup helper that clears
  `SPRITE_OBJECT_BUFFER_CLEAR_BYTES` bytes from `SPRITE_OBJECTS` before
  playfield UI and sprite producers rebuild the logical object slots.
- `docs/source_recovery/sprite_oam.md` records the current OAM/object evidence and open questions.
- The temporary compatibility `DEF` symbols that were needed for later fake-code references have been removed; after the music stream conversion, no references to those fake labels remain.
- `docs/source_recovery/data_ranges.md` records converted and remaining high-priority data ranges.
- Bank 1 range `01:$55E2-$5668` is executable sound setup code. It is now represented as `StartSoundSequence`, because both `SoundEngine` and `SoundLookupIndex` jump to it and it expands a selected sound entry into channel state arrays before returning.
- Bank 1 sound support tables immediately after that code have been split and labeled:
  - `01:$5669` = `SoundWaveDutyData`
  - `01:$566A-$5671` = `SoundRegisterOffsetTable`
  - `01:$5672-$5679` = `SoundChannelDisableMaskTable`
  - `01:$567A-$5681` = `SoundChannelEnableMaskTable`
  - `01:$5682-$5699` = `SoundPitchBaseTable`
- The two sound channel output tables now use `SOUND_OUTPUT_CH1..4_TERMINAL_BITS`
  and `SOUND_OUTPUT_CH1..4_CLEAR_MASK`, matching the `rNR51` left/right
  `AUDTERM_*` bits that `UpdateSoundChannelOutputMask`, rest handling, and
  sequence-end cleanup apply per channel slot.
- The Bank 1 sound support tables now use one record macro per indexed entry:
  `SOUND_WAVE_DUTY_END`, `SOUND_REGISTER_OFFSET_ENTRY`,
  `SOUND_CHANNEL_MASK_ENTRY`, and `SOUND_PITCH_BASE_ENTRY`.
- `SoundPitchBaseTable` was shortened from 13 words to 12 words. `SoundIndexTable` points to `$569A`, proving `$569A` is the first sound sequence byte (`TitleBgmChannel0Sequence`) rather than pitch table data. Its 12 entries are now named `SOUND_PITCH_BASE_INDEX_0..11`, matching the low-nibble index that `SoundUpdate5` receives from note and pitch-slide commands without asserting note letters.
- Bank 1 sequence block `01:$569A-$5FE2` was already mostly `db`, but now has internal pointer-target labels from `TitleBgmChannel0Sequence` and `SoundSequenceData_569c` through `SoundSequenceData_5f30`.
- `SoundIndexEntry_TitleBgm` directly targets four top-level channel streams, now named `TitleBgmChannel0Sequence`, `TitleBgmChannel1Sequence`, `TitleBgmChannel2Sequence`, and `TitleBgmChannel3Sequence`. The change does not infer music phrases inside the stream; the internal `$FD/$FE` join labels stay address-based.
- `TitleBgmChannel1Sequence` now macro-structures its top-level duty/length, vibrato, length/envelope, and octave setup bytes with generic sound-command records, while keeping the note bytes raw.
- `TitleBgmChannel2Sequence` now macro-structures its top-level `$D6,$12` length/envelope setup and four `$FD` sub-sequence calls to `SoundSequenceData_5a34`, using generic sound-command records without naming the repeated phrase.
- `TitleBgmChannel3Sequence` now macro-structures its channel-3 length-scale setup, rest notes, nested-sound note commands, and the unconditional loop in `SoundSequenceData_5a89` without assigning pitch names.
- The same direct sound-index evidence now names the top-level BGM option and preview channel streams: `BgmOption0..2Channel0..3Sequence` and `BgmPreview0..2Channel0..3Sequence`. These names describe the installed channel streams only, not the internal music phrases.
- `BgmOption0*` through `BgmOption2*` and `BgmPreview0*` through `BgmPreview2*` channel heads now macro-structure their high-confidence setup, rest-note, octave, visual-update, vibrato, and frequency-carry command bytes while leaving the longer music phrases raw.
- `MusicSequenceData_60ce` through `MusicSequenceData_6158`, the BGM preview 0 channel-3 visual-update loop labels, now macro-structure their `$F1`, `$C*`, `$D8`, and `$FE` command bytes as visual-update, rest-note, channel-3 length-scale, and loop records.
- The same channel-3 visual-update loop structure is now exposed for BGM preview 1 and 2: `MusicSequenceData_64f0` through `656e` and `MusicSequenceData_6b2a` through `6c9b` use generic visual-update, rest-note, channel-3 length-scale, and loop records.
- Direct sound-index evidence also names link-role and result/menu sound channel entries. `SoundIndexEntry_LinkMaster` and `SoundIndexEntry_LinkSlave` share `LinkRoleSharedChannel0Sequence` and split channels 1-3 into master/slave names. Confirm and link-result entries now use `ConfirmChannel*Sequence`, `LinkResultNonzeroChannel*Sequence`, `LinkResultZeroChannel*Sequence`, `LinkResultConfirmWaitChannel*Sequence`, and `LinkResultMenuWaitChannel*Sequence` for their top-level installed streams.
- The link-role channel heads now macro-structure their parser-confirmed setup, rest, octave, sub-sequence call, and loop records. The one `LinkSlaveChannel3Sequence` call remains byte-split with `LOW`/`HIGH` to preserve the existing `MusicSequenceData_71e4` boundary inside its operand.
- `ConfirmChannel0..3Sequence` now macro-structure their parser-confirmed setup, pitch-slide, rest, channel-3 nested-sound-note, and sequence-end records while leaving pitch/duration bytes raw.
- `LinkResultNonzeroChannel0..2Sequence` and `LinkResultZeroChannel0..2Sequence` now macro-structure their parser-confirmed setup, rest, octave, and sequence-end records while leaving pitch/duration bytes raw.
- `LinkResultConfirmWaitChannel0..3Sequence` and `LinkResultMenuWaitChannel0..3Sequence` now macro-structure their setup records and the associated `$FD` sub-sequence call / `$FE` loop branches. Their shared phrase labels now also expose high-confidence octave, rest-note, channel-3 nested-sound-note, loop, and sequence-end records, and the remaining inline confirm/menu wait phrases now expose high-confidence octave/rest-note command bytes while leaving pitch/duration bytes raw.
- The final named result/preplay sound-index entries now also have top-level channel labels: `Result1PNoRankChannel*Sequence`, `Result1PRankedChannel*Sequence`, `TwoPlayerPreplayMasterInitChannel*Sequence`, `TwoPlayerPreplaySlaveInitChannel*Sequence`, `Result2PNonzeroRankChannel*Sequence`, and `Result2PZeroRankChannel*Sequence`.
- The 1P result channel heads now macro-structure their high-confidence setup, rest-note, octave, vibrato, frequency-carry, and sequence-end command bytes while leaving pitch/duration bytes raw.
- The 2P result channel heads now macro-structure their high-confidence setup, rest-note, octave, pitch-slide, frequency-carry, and sequence-end command bytes while leaving pitch/duration bytes raw.
- `TwoPlayerPreplayMasterInitChannel0/1Sequence` and `TwoPlayerPreplaySlaveInitChannel0/1Sequence` now macro-structure their top-level setup commands with `SOUND_TEMPO`, `SOUND_MASTER_VOLUME`, `SOUND_DUTY_LENGTH`, `SOUND_LENGTH_ENVELOPE`, `SOUND_REST_NOTE`, and `SOUND_FREQ_CARRY_TOGGLE` records where the parser command shape is proven.
- The 2P preplay-init phrase labels `MusicSequenceData_7965`, `79c3`, `7a2b`, and `7a8c` now macro-structure their high-confidence length/envelope, octave, and loop command bytes while leaving pitch/duration bytes raw.
- `MusicSequenceData_7bdf`, the link field-rise sound stream, now macro-structures its high-confidence gate-flag, duty/length, length/envelope, octave, extended-note, pitch-slide, and sequence-end command bytes while leaving note bytes raw.
- Bank 1 music sequence data labels were added at exact `yoshi.sym` data boundaries:
  - `01:$7191-$71C0` = `MusicSequenceData_7191`
- Bank 1 apparent-code music sequence blocks were recovered as data:
  - `01:$5FE3-$7190` = `MusicSequenceData_5fe3` through `MusicSequenceData_6f92`
  - `01:$71C1-$71E3` = `MusicSequenceData_71c1` with internal boundaries at `MusicSequenceData_71c2` and `MusicSequenceData_71d5`
  - `01:$71E4-$77B5` = `MusicSequenceData_71e4` through `MusicSequenceData_779b`, including the earlier `$73B3` fake-code island
  - `01:$77B6-$7805` = `MusicSequenceData_77b6` with an internal boundary at `MusicSequenceData_77c5`
- Bank 1 range `01:$7806-$7C01` was recovered as music sequence data with internal labels at local `$FD/$FE` pointer targets.
- Bank 1 range `01:$7C02-$7C07` is a real six-byte helper reached by two Bank 0 `call $7c02` sites. It is now labeled `TickBgmPreviewTimer`; the adjacent `ApplySoundVisualUpdateCommand` routine still starts at `01:$7C08`.
- The Bank 1 sound/music stream is now explicit data from `01:$569A-$7C01`, with first-pass labels at `$FD/$FE` pointer targets.
- Bank 1 tail data was recovered:
  - `01:$7C2C-$7D84` = `SoundIndexTable`, a 115-entry table of one flags byte plus one sequence pointer.
  - `01:$7DBD-$7DCE` = `SoundWavePatternPointerTable`, used by wave-channel note processing.
  - `01:$7DCF-$7FFE` = wave pattern bytes and short sound sequence data, replacing fake `Call_001_7f9d`/`jr_001_7*` labels.
- Bank 1 VBlank now calls `UpdateSoundChannels`, not a link-state routine. It scans eight active channel slots, pause-gates primary channels 0-3, and calls `TickSoundChannel` for per-channel note length, duty rotation, pitch slide, delay, and vibrato updates.
- `HandleWaveUpdate` is distinct from the normal `ProcessNote` wave-pattern copy. `ProcessNote` loads selected 16-byte wave patterns from `SoundWavePatternPointerTable`; `HandleWaveUpdate` handles the `WAVE_UPDATE` flag by filling wave RAM with `SOUND_WAVE_RAM_FILL_VALUE` through `SOUND_WAVE_RAM_END_LOW`, enabling channel 3 output with `SOUND_WAVE_OUTPUT_TERMINAL_BITS`, triggering `rNR34` with `SOUND_WAVE_TRIGGER_VALUE`, and shifting bytes from the `UpdateSoundChannels` code stream into `rNR32` until `SOUND_WAVE_UPDATE_END_MARKER`.
- Bank 1 wave-pattern labels no longer depend on source addresses:
  `SoundWavePatternPointerTable` emits nine `SOUND_WAVE_PATTERN_POINTER`
  records selecting `SoundWavePatternData_0..2`, which are now emitted as
  paired 8-byte `SOUND_WAVE_PATTERN_ROW` records. Selector values that point
  at `$7DFF` use the factual `SoundWavePatternData_SharedSequence` alias for
  the same address as `SoundSequenceData_7dff`; that shared bytestring stays as
  sequence `db` because the first 16 bytes are dual-use.
- Sound-engine `$FF` literals in executable paths now use scoped constants:
  `SOUND_WAVE_RAM_FILL_VALUE` for the `HandleWaveUpdate` fill,
  `SOUND_SEQUENCE_END_COMMAND` for parser end bytes,
  `SOUND_VIBRATO_FREQ_MAX` for positive vibrato overflow clamp,
  `SOUND_REGISTER_PAGE_HI` for `$FFxx` hardware register addressing, and
  `SND_STOP_ALL` for the external sound command.
- Bank 1 sound parser locals now expose the first command-layer structure: `$FF` / `SOUND_SEQUENCE_END_COMMAND` end handling returns from saved `$FD` / `SOUND_SUBSEQUENCE_CALL_COMMAND` subsequences or clears/mutes active channel state, `$FE` / `SOUND_LOOP_JUMP_COMMAND` either increments a loop counter or jumps to a sequence target, `$D0-$DF` / `SOUND_LENGTH_ENVELOPE_COMMAND_BASE` stores length scale and wave/envelope fields, `$E8` / `SOUND_FREQ_CARRY_TOGGLE_COMMAND` toggles flag bit 0, `$EA` / `SOUND_VIBRATO_COMMAND` loads delay/vibrato state, and `$EB` / `SOUND_PITCH_SLIDE_COMMAND` enters the pitch-slide setup path.
- The next Bank 1 sound parser command checks are now behavior-named as well: `$EC` / `SOUND_DUTY_LENGTH_COMMAND` stores duty/length bits, `$ED` / `SOUND_TEMPO_COMMAND` updates main or SFX tempo pairs and clears their accumulators, `$EE` / `SOUND_OUTPUT_MASK_COMMAND` stores `SOUND_OUTPUT_MASK`, `$EF` / `SOUND_NESTED_SOUND_COMMAND` starts a nested sound and preserves/dequeues `SOUND_DEFERRED_ID`, `$FC` / `SOUND_DUTY_ROTATE_COMMAND` stores duty-rotate state and sets flag bit 6, and `$F0` / `SOUND_MASTER_VOLUME_COMMAND` writes `rNR50`.
- The following parser command checks are also named: `$F1` / `SOUND_VISUAL_UPDATE_COMMAND` calls `ApplySoundVisualUpdateCommand`, `$F8` / `SOUND_GATE_FLAG_COMMAND` sets `SOUND_CH_GATE_SUPPRESS_BIT` in `SOUND_CH_GATE_FLAGS`, `$E0-$EF` / `SOUND_OCTAVE_COMMAND_BASE` unhandled high-nibble commands store the low nibble in `SOUND_CH_OCTAVE`, `$10` / `SOUND_SWEEP_COMMAND` writes `rNR10`, `$20-$2F` / `SOUND_EXTENDED_NOTE_COMMAND_BASE` handles extended note data for channels 3-7 when the gate-suppress bit is clear, `$B0-$BF` / `SOUND_CHANNEL3_NESTED_COMMAND_BASE` can trigger a nested sound through `SoundEngine` unless `SOUND_DEFERRED_ID` is already set, and `$C0-$CF` / `SOUND_REST_NOTE_COMMAND_BASE` enters the rest/silent-note path.
- `SoundSequenceData_7d85..7db9` are early channel-7 effect sequences reached
  directly by `SoundIndexTable` entries. Each now uses
  `SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE param0, param1`, which emits
  `SOUND_EXTENDED_NOTE_COMMAND_BASE`, two channel-7 operands, and
  `SOUND_SEQUENCE_END_COMMAND`. The operand names stay generic until the
  channel-7 hardware write semantics are fully decoded.
- `SoundSequenceData_7e15` is the channel-5 half of the two-entry pause sound
  (`SoundIndexEntry_Pause` plus `SoundIndexEntry_2f`). It now uses generic
  `SOUND_DUTY_LENGTH`, `SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END`
  records. The paired `SoundSequenceData_7dff` stays raw because the same
  bytes are also selected by the wave-pattern pointer table.
- `SoundSequenceData_7e67..7ea9` are the channel-4 board-scan step effect
  sequences selected by `SoundIndexEntry_BoardScanStep0..6`. They now use
  `SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE duty, sweep, note, envelope, freq_lo,
  freq_hi, final_sweep`; all seven records share the same command layout and
  differ only in the explicit frequency-low operand (`$C0` down to `$00`).
- `SoundSequenceData_7e2c`, `SoundSequenceData_7eb4`, and
  `SoundSequenceData_7ec7` now use generic sound-command records:
  `SOUND_DUTY_LENGTH`, repeated `SOUND_EXTENDED_NOTE`, and
  `SOUND_SEQUENCE_END`. This documents the command bytes used by
  `SoundIndexEntry_DropStart` and the adjacent two-entry board-scan effect
  pair without assigning names to the three extended-note operands yet.
- `SoundSequenceData_7e4b`, `7e5c`, `7eda`, `7eeb`, `7ef6`, `7f29`,
  `7f34`, `7f43`, `7f52`, and `7f9d` now expose their short channel-4
  command streams with `SOUND_DUTY_LENGTH`, `SOUND_SWEEP`,
  `SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END` records. These labels cover
  commit/place/land/cursor/matching/round-complete sound-index entries while
  keeping the extended-note operands generic.
- `SoundSequenceData_7f0d`, `7fb4`, `7fd0`, and `7fe3` now use the same
  generic duty/extended-note/end records. `7f0d` and `7fb4` intentionally fall
  through to end-only labels at `SoundSequenceData_7f1b` and
  `SoundSequenceData_7fc2`. The adjacent channel-7 entries
  `SoundSequenceData_7f1c` and `7fc3` now use `SOUND_CHANNEL7_EXTENDED_NOTE`
  records for their two-operand extended-note commands. The final sequence ends
  at `01:$7FF5`; the remaining `01:$7FF6-$7FFF` bytes are now
  `Bank1TailPaddingData`, five repeated little-endian `$3900` padding words.
- `SoundSequenceData_7f65` and `7f80` now expose their mixed command tails with
  generic `SOUND_GATE_FLAG`, `SOUND_LENGTH_ENVELOPE`, `SOUND_OCTAVE`, and
  `SOUND_PITCH_SLIDE` records after the extended-note runs. The
  `SOUND_LENGTH_ENVELOPE` macro covers the `$D0-$DF` command form that consumes
  the following parameter byte on these channels.
- `SOUND_CH_FLAGS` bit uses are now named where the current parser/update code
  proves them: frequency carry toggle, `$FD` return pending, note-output gate,
  vibrato subtract phase, pitch-slide active/descending state, and duty-rotate
  active state.
- Sound parser/setup channel-index comparisons now use named constants for the
  primary channel split, last channel, primary/secondary wave channels, and the
  channel-3 nested/extended-command branch.
- Bank 1 sound reset/setup paths now name shared defaults:
  `SOUND_COUNTER_INIT_VALUE` (`$01`) for loop/note/length/tempo high defaults,
  `SOUND_OUTPUT_MASK_ALL` (`$FF`) for the reset output mask, and
  `SOUND_NR50_RESET_VALUE` (`$77`) for the master volume/mixing register value.
- `TickSoundChannel` now uses `SOUND_NOTE_LENGTH_SEQUENCE_STEP_VALUE` for the
  note-length value that advances the parser instead of decrementing the
  channel timer. The wave-channel paths now name
  `SOUND_WAVE_LEVEL_PARAM_BITS` for the level bits in the length/envelope
  parameter byte and `SOUND_WAVE_PATTERN_LAST_BYTE_INDEX` for the 16-byte
  `_AUD3WAVERAM` copy loop.
- `SoundUpdate5` now names the pitch-table shift target and high-byte bias:
  `SOUND_PITCH_SHIFT_TARGET_OCTAVE` is the stop value for the octave shift
  loop, and `SOUND_PITCH_FREQ_HIGH_BIAS` is added to the shifted pitch high
  byte before it is returned for NRx3/NRx4 writes.
- `SoundEngine` now names the BGM-reset command range: commands at or below
  `SOUND_BGM_RESET_SKIP_MAX_COMMAND` go straight to the sound index lookup,
  while the reset path is entered through `SOUND_BGM_RESET_MAX_COMMAND` for
  the table range that clears primary-channel sound state first. The reset
  path now also names the primary pointer and channel-state clear spans.
- `StopAllSoundHW` now names the shared sound hardware reset bytes:
  `SOUND_HW_RESET_ENABLE_VALUE` powers NR52/NR30 back on,
  `SOUND_HW_RESET_SWEEP_ENV_VALUE` is the `$08` value written to NR10 and the
  envelope registers, and `SOUND_HW_RESET_LENGTH_ON_VALUE` is the NRx4
  length-enable byte. The full reset clear spans are now expressed from the
  sound WRAM layout instead of raw `$A0/$18` byte counts.
- Bank 1 sound update paths now name the high-confidence packed and
  hardware-register helper values: `SOUND_VIBRATO_PHASE_COUNTER_MASK`,
  `SOUND_VIBRATO_DEPTH_SUBTRACT_MASK`,
  `SOUND_VIBRATO_DEPTH_ADD_MASK`, `SOUND_DUTY_BITS_MASK`,
  `SOUND_LENGTH_BITS_MASK`, and the `SoundUpdate3` NRx1/NRx2/NRx3 offsets.
  This confirms `SoundUpdate3` takes channel `C` plus a small hardware-register
  offset in `B` from `SoundRegisterOffsetTable`.
- `SoundRegisterOffsetTable` now names its per-channel hardware base low bytes
  as `SOUND_REGISTER_CH*_BASE_LOW`, derived from the channel register layout
  around `rNR10`, `rNR21`, `rNR30`, and `rNR41`. The low-ID BGM active-state
  setup also names the channel-6 sequence pointer slot offset with
  `SOUND_SECONDARY_WAVE_SEQUENCE_PTR_OFFSET`, matching `C=6` times the
  two-byte sequence-pointer stride.
- Bank 1 sound hardware writes now use scoped hardware constants for the
  pause-applied bit in `SOUND_PAUSE_FLAG`, NR30 wave enable/disable writes,
  silent-rest envelope setup, and the NRx4 restart/high-frequency mask in the
  note trigger path.
- `UseSfxOrFixedSoundTempo` now names the fixed `$0100` tempo multiplier used
  by channel 7 as `SOUND_FIXED_TEMPO_HI/LO`, and the pitch-slide setup path
  names its one-tick underflow clamp as `SOUND_PITCH_SLIDE_MIN_TICKS`.
- The `$FE` sound loop/jump command reset path now reuses
  `SOUND_COUNTER_INIT_VALUE` when a counted loop reaches its operand count and
  skips over the loop-target pointer.
- `RewindSoundSequencePointerAndReturnCarry` now names the one-byte sequence
  pointer rewind as `SOUND_SEQUENCE_REWIND_LOW_BYTE_DELTA` /
  `SOUND_SEQUENCE_REWIND_HIGH_BYTE_DELTA`, making the BGM active-ID gate's
  parser rewind explicit instead of raw `sub $01` / `sbc $00`.
- The Bank 1 note/output layer now has behavior names. `ProcessSoundNoteCommand` computes per-channel note length from the scale/tempo accumulators, handles rest commands and BGM gating, initializes pitched-note output, writes cached envelopes and length registers, applies the output mask to `rNR51`, and then passes the base frequency to `ProcessNote`.
- `ProcessNote` now names the selected wave-pattern copy to `_AUD3WAVERAM` for channels 2/6 and the final frequency/trigger register write for all note channels. The nearby pitch-slide locals now distinguish ascending versus descending setup, step calculation, and frequency storage before writing the updated NRx3/NRx4 pair.
- `SoundLookupIndex` now exposes the channel-priority gate before a new sound entry is installed. Empty channels clear immediately, channel 7 uses the shared `SOUND_BGM_ACTIVE_ID_GATE` low-ID boundary, and the common path clears per-channel state before `StartSoundSequence` fills the sequence pointer and active-ID fields. `ClearSoundChannelAfterEnd`, `UpdateChannel`, and `StartSoundSequence` use the same gate for BGM active-ID and command-ID checks around NR50 restore, sequence rewind, channel-7 priority, and BGM active-state setup.
- `StartSoundSequence` now names the sequence-pointer slot search, channel entry install, and BGM active-state setup. `Yoshi/yoshi.sym` now matches the recovered sound setup/data boundaries: `$55E2-$5668` code, `$5669-$5699` support tables, `$569A-$7C01` sequence data, `$7C02-$7C2B` code, and `$7C2C-$7FFF` sound index/wave/tail data.
- `docs/source_recovery/sound_engine.md` now records the first-pass command format for the Bank 1 sound/music interpreter, including `$FD` sub-sequence calls, `$FE` loops, `$FF` end/return, and the main per-channel state arrays.
- Sound engine WRAM `$C000-$C0ED` is now represented by `SOUND_*` constants in `Yoshi/constants.inc`. High-confidence fields include current/return sequence pointers, active sound IDs, pause gating, output mask, loop counters, wave selectors, and the sound-index temporary pointer; slide/tempo/envelope fields remain medium-confidence and are documented that way.
- High-confidence sound IDs from `PlaySound` call sites are now named (`SND_LINK_FIELD_RISE`, `SND_DROP_START`, `SND_PLACE_PIECE`, `SND_COMMIT_PIECE`, `SND_PIECE_LAND`, `SND_CURSOR_MOVE`, `SND_MATCHING_*`, `SND_ROUND_COMPLETE`, `SND_ROUND_COMPLETE_REVEAL`, `SND_ROUND_COMPLETE_MAJOR_REVEAL`, `SND_PAUSE`, `SND_TITLE_BGM`, `SND_BGM_OPTION*/PREVIEW*`, `SND_LINK_MASTER/SLAVE`, `SND_CONFIRM`, the `SND_LINK_RESULT_*` result-screen wait/terminal sounds, the `SND_RESULT_*` `ProcessRoundResultAndEnterRoundEnd` result/rank sounds, and `SND_STOP_ALL`) and matching alias labels were added to `SoundIndexTable`.
- A follow-up direct-call audit after the link-result helper rename found no
  remaining raw `ld a, $xx` immediately before `PlaySound` in Bank 0/1. The
  remaining numeric `SoundIndexEntry_XX` labels therefore stay scoped as
  unclassified table entries until sequence-internal `$EF` commands or another
  producer prove a player-visible role.
- `SoundIndexTable` now uses `SOUND_INDEX_ENTRY` records and explicit
  count/channel flag constants for each first byte:
  `SOUND_INDEX_ENTRY_COUNT_1..4` are the total adjacent entries expanded by
  `SoundLookupIndex` / `StartSoundSequence`, and `SOUND_INDEX_ENTRY_CHANNEL_0..7`
  are the target channel slots. Entry `$00` now uses
  `SOUND_INDEX_ENTRY_SENTINEL_FLAGS` /
  `SOUND_INDEX_ENTRY_SENTINEL_POINTER`; it remains scoped as sentinel data
  because no live sound command is confirmed to use it.
- Round-complete reveal sound ID `$12` is used for the default transition sound
  and the 200/100/50-point A-type bonus reveal stages. `$16` is used for the
  major transition frame and the 500-point reveal stage.
- `DrawLandedPieceAndUpdateColumnTop` now uses `SND_PLACE_PIECE` for the direct
  nonmatching/terminal-row placement path. `CommitFallingPieceToBoard` now uses
  `SCORE_DELTA_COMMIT_PIECE` (`00005` packed BCD) before advancing the selected
  column top row and spawning the field-column effect.
- Bank 0 range `00:$15FE-$1611` is `LevelFallDelayTable`, not code. `GetLevelFallDelay` indexes it by capped `PROGRESSION_LEVEL` to seed the fall timer, and the entries are now emitted as `LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_0..19`. The real code entry at `00:$1612` is `HandleMatchedLandingScanState`, falling through to `CommitFallingPieceToBoard` at `00:$162A`.
- Bank 0 range `00:$0B8D-$0ED4` is a 4-byte-stride game-turn parameter table. `InitGameTurnPieceDisplay` seeds `GAME_TURN_TABLE_INDEX` from `GameTurnLevelStartIndexTable`, and `LoadGameTurnPieceDisplayStep` reads `GameTurnParamTable + index * 4` to reload `GAME_TURN_STEP_TIMER`, choose the count passed to `BuildPieceDisplayStatesForCount`, and reload `GAME_TURN_DELAY`. The table contains 210 records; the fourth byte is `$01` in every record, but no reader for that tail byte has been confirmed.
- `GameTurnParamTable` now uses a `GAME_TURN_PARAM` macro for all complete
  records, exposing the three consumed bytes and emitting the constant unread
  tail byte. The `GameTurnParamTableContinuation` exact-address label falls one
  byte before a record boundary, so the crossing record uses
  `GAME_TURN_PARAM_SPLIT_HEAD` before the label and
  `GAME_TURN_PARAM_SPLIT_TAIL` after it to keep `00:$0C40` stable.
- The game-turn table index control now names the no-increment sentinel
  (`GAME_TURN_TABLE_INDEX_SENTINEL`) and the observed loop boundary
  (`GAME_TURN_TABLE_LOOP_END_INDEX` back to
  `GAME_TURN_TABLE_LOOP_RESTART_INDEX`).
- The game-turn delay loaders each contain an unreachable `ld b,$02` clamp
  fragment after an unconditional `jr` to the delay store. These are now labeled
  `UnreachedGameTurnDelayClamp` and `UnreachedInitialGameTurnDelayClamp`, using
  `PIECE_FALL_DELAY_MIN` for the literal without changing the assembled bytes.
- Piece-display object builders now use named slot mechanics:
  `SPRITE_OBJECT_PHASE_WAIT` for the initial wait phase,
  `GAME_OVER_PIECE_DISPLAY_SLOT_OFFSET` for the slots 5-8 mapping, and
  `PIECE_DISPLAY_OBJECT_CLEAR_SLOT_ADVANCE` for clearing type/frame fields.
- `BuildPieceDisplayStatesForCount` now names the one-shot special-selection skip threshold and
  active value as `PIECE_DISPLAY_SKIP_SPECIAL_MIN_COUNT` and
  `PIECE_DISPLAY_SKIP_SPECIAL_ACTIVE`. The timer-gated force paths now store
  `PIECE_DISPLAY_FORCE_FLAG_ACTIVE`, and the display-state clear pass uses
  `PIECE_DISPLAY_STATE_EMPTY`.
- `BTypeColumnTopRowSeedTable` is the B-type setup table indexed by
  `ACTIVE_LEVEL` to choose `COLUMN_TOP_ROW_SEED`. The same setup path seeds
  `PIECE_DISPLAY_COUNT` with `B_TYPE_INITIAL_PIECE_DISPLAY_COUNT`, and the fill
  wrapper's `VBLANK_BUSY` delay is named as
  `INITIAL_BOARD_FILL_VBLANK_WAIT_FRAMES`.
- `BTypeColumnTopRowSeedTable` entries are now expressed as
  `B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_0..4`,
  descending by `BOARD_CELL_STRIDE` from `BOARD_COLUMN_BOTTOM_VISIBLE_OFFSET`.
  The previous
  threshold-style label is now `GameTurnLevelStartIndexTable`, whose entries
  use `GAME_TURN_LEVEL_START_INDEX_ENTRY GAME_TURN_LEVEL_*_START_INDEX`
  constants in ten-record steps.
- Bank 0 range `00:$117C-$11EF` is matching/result data, not executable code. It contains three shadow-OAM templates, a `STATE_TRANSITION * 2` big-endian BCD score table for `AddScore`, and a 28-byte tile-base index table. The score table now uses `SCORE_DELTA_ENTRY` records for the named packed-BCD `MATCHING_SCORE_BONUS_DELTA_*` values. The tile-base table now uses `MATCHING_TILE_BASE_INDEX_ENTRY` records with values expressed as `MATCHING_TILE_BASE_INDEX_STATE_0..27`, matching the capped `MATCHING_STATE_COUNT` range before scaling by `MATCHING_MIDDLE_OAM_TILE_INDEX_SHIFT` for the middle OAM template or `MATCHING_FINAL_OAM_TILE_INDEX_SHIFT` for the final OAM pair. The following `00:$11F0-$1202` bytes are left as a coherent but unreferenced helper, now labeled `UnusedDrawVerticalTilePairUnlessFF`; its skip value and tile base are now named as `UNUSED_VERTICAL_TILE_PAIR_SKIP_VALUE` and `UNUSED_VERTICAL_TILE_PAIR_TILE_BASE`.
- Bank 0 range `00:$18CB-$18E3` is board-scan transition/reward data after
  `FinishBoardScanNoTargetLanding`, not code. `$18CB-$18D1` is
  `BoardScanTransitionFrameLimitTable`, selected from the pre-remap
  `SCREEN_STATE`; its entries now use
  `BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY` records with
  `BOARD_SCAN_TRANSITION_FRAME_LIMIT_1..4`, and the send loop emits frames
  from `ROUND_TRANSITION_FRAME_START` through the selected limit.
  `$18D2-$18E3` is `BoardScanRewardScoreDeltaTable`, a big-endian BCD
  score-delta table loaded into `HL` before calling `AddScore`. Its entries
  use `SCORE_DELTA_ENTRY` records for the named 50/100/200/500-point
  packed-BCD deltas.
  `BuildPieceDisplayObjects` starts at `00:$18E4`.
- Bank 1 `01:$432F` is now labeled `AddScore`. It adds an `HL` packed-BCD score delta into `$C61D-$C61F`, caps at `99999`, and writes five unpacked display digits at `$C621-$C625`.
- Bank 1 `01:$4321` is now labeled `UnusedDrawLowNibbleTileDigitsByCoord`. The current source has no call/jump reference to this helper, and it sits after the countdown tile-slot routine's `ret`.
- Bank 1 `01:$4394` is now labeled `UnusedDrawTwoDigitBcdTilePair`. The current source has no call/jump reference to it, and it is preceded by a `ret` plus an unreferenced two-instruction setup fragment.
- Bank 1 `01:$442C-$445B` is `FieldColumnTilePatternTable`, three 16-byte tile
  patterns selected by `DrawFieldColumnTilePattern`; `01:$445C` is real code and is now
  labeled `StartNextRound`. The table now uses six
  `FIELD_COLUMN_TILE_PATTERN_ROW` rows whose `BLANK`, `LEFT_MARKER`, and
  `RIGHT_MARKER` roles map to `GRID_COLUMN_CLEAR_TILE` and the playfield
  bottom-column marker tiles.
- Bank 1 `01:$465D` is now labeled `DrawPlayfieldEggCountDigits`; it renders `EGG_COUNT_ONES` / `EGG_COUNT_TENS` as tile IDs `$40+digit` in the gameplay display.
- Bank 1 `01:$4681` is now labeled `IncrementEggCountAndRefreshDisplay`; it advances `EGG_COUNT_ONES` / `EGG_COUNT_TENS` / `EGG_COUNT_HUNDREDS` as decimal digits capped at 999 and is called from the round-complete score/result path.
- Bank 1 level and egg display locals now have behavior labels:
  `IncrementATypeLevelDisplayDigits`, `StoreATypeLevelDisplayOnes`,
  `IncrementLevelDisplayDigits`, `StoreLevelDisplayOnes`,
  `UseEggTextFrame0..2`, `DrawEggTextFrameRows`, `UseATypeEggCountCoord`,
  `DrawPlayfieldEggCountDigitsAtCoord`, and `RefreshEggCountDigitsAfterIncrement`.
- Egg text pulse locals now name the frame-2 draw, frame toggle, and pulse
  completion return path: `DrawEggTextPulseFrame2`,
  `ToggleEggTextPulseFrame`, and `ReturnAfterEggTextPulseComplete`.
- `$C6D2` is now `EGG_COUNT_UNUSED_BYTE`: init paths clear it with the egg counter, but no direct read has been confirmed.
- `$C6EB/$C6EC` are the local 2P selected level/speed bytes; `Exchange2PPreplaySettings` packs them into one link byte, while the receiver masks the high/low nibbles with `LINK_SETTINGS_NIBBLE_MASK` and stores them in `LINK_RECV_LEVEL` / `LINK_RECV_SPEED` at `$C6FF/$C700`.
- `$C6FC/$C6FD` are a two-byte link send queue selected by `$C6FE`; `TimerTickCore` sends one queued byte per tick and clears the slot afterward.
- `ClearLinkRoundState` now names the Bank 1 helper that clears the round-local link staging bytes: `LINK_SEND_QUEUE_INDEX`, `LINK_PENDING_FIELD_RISE`, `LINK_SEND`, `LINK_RECV`, `LINK_UNUSED_STAGING_BYTE`, both link send queue slots, and `LINK_FIELD_EVENT_PAYLOAD`.
- `$C6F0` is the 2P pre-play settings cursor, now named `LINK_SETTINGS_CURSOR`; row `0` selects `LINK_2P_SELECTED_LEVEL` and row `1` selects `LINK_2P_SELECTED_SPEED`.
- `$C6F1/$C6F2` are the shared settings/result blink phase and timer, now named `SETTINGS_BLINK_PHASE` and `SETTINGS_BLINK_TIMER`. The phase toggles every `$0F` frames via `SETTINGS_BLINK_PHASE_TOGGLE_MASK`, and selected rows use it to draw blank text/markers during the blink interval.
- `GAME_STATE_PREPLAY_LOOP` now calls `RunPreplayLoop`, which dispatches to `Run1PPreplayLoop` for the 1P option/settings path and `Run2PPreplayLoop` for the 2P link-start path.
- The 2P pre-play loop's local input branches are now named.
  `Check2PPreplayReceivedStartHandshake` and `Enter2PPreplayPlaySetup` cover
  the `LINK_CONFIRM_BYTE` start handshake, `Handle2PPreplayNonStartInput` dispatches
  non-Start inputs,
  `Move2PPreplayCursorUp` / `Move2PPreplayCursorDown` clamp
  `LINK_SETTINGS_CURSOR` between the level and speed rows, and
  `Increment2PPreplaySelectedSetting` / `Decrement2PPreplaySelectedSetting`
  edit the selected `LINK_2P_SELECTED_LEVEL` or `LINK_2P_SELECTED_SPEED` byte.
  `LinkSettingsOptionCountTable` now emits `LINK_SETTINGS_OPTION_COUNT_ENTRY`
  records for the exclusive upper bounds: `LINK_SETTINGS_LEVEL_OPTION_COUNT`
  and `LINK_SETTINGS_SPEED_OPTION_COUNT`.
- The 1P pre-play loop's local input branches are now named. `Handle1PPreplayNonStartInput` dispatches non-Start presses, `Move1PPreplayCursorUp` / `Move1PPreplayCursorDown` clamp `MENU_CURSOR` between `MENU_CURSOR_ROW_GAME_TYPE` and `MENU_CURSOR_ROW_BGM`, and `Increment1PPreplaySelectedOption` / `Decrement1PPreplaySelectedOption` edit the selected option byte, calling `ApplyGameSettings` immediately when the BGM row changes. `DetachedPreplayOptionCountTable` and `PreplayLoopOptionCountTable` emit `PREPLAY_OPTION_COUNT_ENTRY` records for `OPTION_GAME_TYPE_OPTION_COUNT`, `OPTION_LEVEL_OPTION_COUNT`, `OPTION_SPEED_OPTION_COUNT`, and `OPTION_BGM_OPTION_COUNT` as the four exclusive upper bounds. The BGM marker path now names value 3 as `OPTION_BGM_OFF_VALUE`, and the detached option redraw path names the low-byte comparison against `OPTION_BGM` as `OPTION_BGM_ADDR_LO`.
- The detached, live 1P, and live 2P pre-play non-Start input dispatchers now
  use `PADB_UP`, `PADB_DOWN`, `PADB_RIGHT`, and `PADB_LEFT` instead of raw
  normalized joypad bit numbers.
- The former `DrawCountdownNum` helper is now `ClearSettingsCursorFrameHighBits`.
  It is called after accepted 1P pre-play input and masks the frame bytes of
  settings cursor slots 9-11; it is not part of countdown digit rendering.
- `ApplySettings` now names the 7-byte settings cursor init record size and the
  init record fields/positions for `SettingsCursorSpriteInit0..2`: type,
  unused byte, frame/toggled-frame pair, shared base Y, unused grid-column byte,
  and the three base-X positions. The three records now use
  `SETTINGS_CURSOR_INIT_RECORD frame, base_x`.
- `OptionMarkerPositions` now derives its row/column bytes from the
  `OPTION_MARKER_*_COORD` constants used by the selected-marker draw paths
  through `OPTION_MARKER_POSITION` records, keeping the clear-all and
  draw-selected marker positions tied together.
- The option cursor triplet data labels now describe their roles:
  `OptionCursorInactiveTileTriplets` for the neutral redraw and
  `OptionCursorLevelHighlightTileTriplets` /
  `OptionCursorSpeedHighlightTileTriplets` /
  `OptionCursorBgmHighlightTileTriplets` for the selected row overlays; each
  row/column/tile tuple now uses `DRAW_TILE_TRIPLET`.
- The option redraw path now names the frame-tile offset values passed in `d`:
  `OPTION_BOX_NEUTRAL_TILE_OFFSET` for the normal option boxes and
  `OPTION_BOX_SELECTED_TILE_OFFSET` for the highlighted game-type/level boxes.
  The remaining option UI value comparisons in this path now use
  `MENU_CURSOR_ROW_*`, `OPTION_LEVEL_VALUE_1..3`, and the existing
  `OPTION_BGM_VALUE_1/2` constants instead of raw small immediates.
- The option box drawing helpers now have behavior names:
  `DrawOptionBoxLayout`, `DrawOptionLevelValueBoxes`,
  `DrawOptionBoxAtCoord`, `FillOptionBoxHorizontalRun`, and individual
  `DrawOption*Box` labels for the game-type, level, speed, and BGM frames.
- The option box geometry and frame tiles are now named. The decoration strip
  uses `OPTION_DECORATION_*` constants; the shared box renderer uses
  `OPTION_BOX_TOP_LEFT_TILE_BASE` through
  `OPTION_BOX_BOTTOM_RIGHT_TILE_BASE`; individual option boxes use
  `OPTION_BOX_*_COORD` and `OPTION_BOX_*_INNER_SIZE` constants.
- The code bytes immediately after `RunPreplayLoop` are still assembled as a
  pre-play-like input handler, but the live state `$05` dispatch uses
  unconditional jumps to `Run1PPreplayLoop` or `Run2PPreplayLoop` before that
  fragment. The recovered labels therefore use `DetachedPreplay*` names and do
  not supersede the canonical 1P/2P pre-play loop labels. The detached
  label-tile tail after `BgmMarkerNoneText` now reuses the shared
  `PREPLAY_LEVEL_LABEL_*` tile-row constants and
  `PREPLAY_LABEL_TILE_ROW_WIDTH`.
- The 1P pre-play screen helpers now use `Draw1PPreplay*` names. They draw
  the 1P pre-play background, header, option labels, option text, speed text,
  level text, game-type text, and BGM marker; they are not win/lose/game-over
  logic. `Draw1PPreplayBackground` now names the full-screen fill, the four
  option panel rectangles, and the background/panel-clear tiles. The 1P
  pre-play game-type, level, speed, and BGM label/text coordinates are also
  named; the level/speed label tile rows are shared with the 2P setup screen,
  and `PREPLAY_LABEL_TILE_ROW_WIDTH` names the four-tile label run length.
  The BGM marker strings now reuse `OPTION_MARKER_SELECTED_TILE` and
  `OPTION_MARKER_BLANK_TILE`.
- The 2P pre-play screen helpers now use `Draw2PPreplay*` names. They draw the
  two-player setup background, role header/panels, level/speed labels, and
  local/peer setting text, with `SETTINGS_BLINK_PHASE` blanking the selected
  local row. `Draw2PPreplayBackground` now names the full-screen fill, upper
  and lower six-row panels, and the background/panel-clear tiles; its
  level/speed label tile rows reuse the shared pre-play label constants and
  `PREPLAY_LABEL_TILE_ROW_WIDTH`. The
  role header, master/slave role panel tile bases, local/peer level preview
  coordinates, and local/peer speed text coordinates are now named by their
  observed screen positions and link-role swap behavior.
- Start-button checks in the title, pre-play, pause, and link-result confirm
  paths now use the RGBDS hardware constants `PADB_START` / `PADF_START`
  instead of raw bit/value `$03` / `$08`. `LINK_ROLE_MASTER` now names the
  `$01` link-role comparisons and stores; `LINK_ROLE_SLAVE` was already used
  for the `$02` role.
- Link serial control now names the common `rSC` start values as
  `SERIAL_TRANSFER_INTERNAL_CLOCK` / `SERIAL_TRANSFER_EXTERNAL_CLOCK`, the
  serial completion flag value as `SERIAL_DONE_ACTIVE`, the shared `$55`
  start/result confirmation byte as `LINK_CONFIRM_BYTE`, the unassigned-role
  ready byte as `TITLE_LINK_READY_BYTE`, and the pause packet as
  `LINK_PAUSE_PACKET`. The unassigned-role fallback also names the observed
  `SERIAL_DIV_RESET_WRITE_VALUE` written to `rDIV` before restarting the
  external-clock transfer. The two-slot send queue wrap now uses
  `LINK_SEND_QUEUE_SLOT_COUNT`.
- The 2P result/high-score screen now names its role-swapped header/badge tile
  bases, terminal outcome/status tile bases, wait-panel tile pairs, score
  clear/fill areas, and confirm-panel tile/rect constants. These names remain
  tied to layout and branch roles; they do not assign final text semantics to
  the tile art.
- The 2P result/high-score sound IDs `$58/$5B/$5E/$62` are now named as
  `SND_LINK_RESULT_NONZERO`, `SND_LINK_RESULT_ZERO`,
  `SND_LINK_RESULT_CONFIRM_WAIT`, and `SND_LINK_RESULT_MENU_WAIT`. The names
  come from the terminal result branch and the active-sound guards in
  `WaitLinkStartConfirm` / `WaitTerminalLinkResultMenuConfirm`.
- The link result confirm path now uses role-specific wait names instead of
  generic menu/sound/serial labels. `WaitTerminalLinkResultMenuConfirm` returns
  carry for the terminal zero-result menu wait, while
  `DrawLinkResultConfirmPanelsAndWait` draws the normal confirm panels and
  falls through to `WaitLinkResultConfirmAndReloadTiles`, which clears serial
  state, waits for master Start or peer `$55`, reloads game tiles, and returns
  without carry.
- Bank 0 serial/text/pre-play-init local tails are now named. `SerialHandler`
  exits through `FinishSerialInterrupt`, the no-role path is
  `HandleUnassignedSerialRole`, `DrawStringToGrid` uses
  `CopyStringToGridLoop` / `AdvanceStringGridRow`, and
  `StartGameplay` enters the 2P setup tail through `InitTwoPlayerPreplayScreen`.
- `Exchange2PPreplaySettings` now names the 2P pre-play settings exchange wait:
  `Start2PPreplaySettingsExchange` starts the master serial transfer,
  `Wait2PPreplaySettingsSerialDone` waits for completion, and a received
  `LINK_CONFIRM_BYTE` exits as the start handshake before unpacking peer
  level/speed nibbles.
- Field animation step routines now use `EndFieldAnimSlot10..13` labels for
  the sentinel cleanup tails that clear active flags, cursors, and logical
  sprite object type bytes.
- `GAME_STATE_TITLE_MENU` now calls `RunTitleMenu`, a per-frame title loop that clears scratch bytes, updates the 1P/2P selection, and handles Start/link entry into `GAME_STATE_PREPLAY_INIT`.
- `$C7AE-$C7CD` are four countdown digit bitmap staging buffers. `UpdateCountdownTimer` builds them from `SCORE_BCD_*` and `CountdownDigitPatternTable`; `RandomNext` copies buffer pairs to `COUNTDOWN_BLIT_DEST_PHASE0` / `COUNTDOWN_BLIT_DEST_PHASE1`.
- `$C7CE/$C7CF` are the countdown digit blit timer/phase bytes. `Draw1PCountdownDigitTileSlots` seeds the timer with `2`, `UpdateCountdownTimer` toggles the phase, and `RandomNext` decrements the timer after each blit.
- The countdown digit buffer build now names the phase toggle, high/low nibble
  masks, and the phase-1 spill pixel mask used while merging shifted digit
  bitmap columns from `CountdownDigitPatternTable`.
- `CountdownDigitPatternTable` now uses ten `COUNTDOWN_DIGIT_PATTERN` records,
  matching the 8-byte digit bitmap stride used by the countdown buffer build.
- Countdown digit buffer local loops are now named by buffer pair. Phase 0
  builds buffers 2/3 and blits them through
  `BlitCountdownPhase0Buffer2Loop` / `BlitCountdownPhase0Buffer3Loop`; phase 1
  builds buffers 0/1 and blits them through
  `BlitCountdownPhase1Buffer0Loop` / `BlitCountdownPhase1Buffer1Loop`.
- Bank 1 countdown/playfield helpers now have behavior labels:
  `Draw1PCountdownDigitTileSlots` draws the 1P countdown tile slots and queues
  the digit-buffer blit, `ClearScoreAccumulatorAndDigitsLoop` clears the score
  accumulator/display digit range while preserving the score-adjacent flag, and
  `CopyFieldColumnTilePatternLoop` copies the selected field-column tile pattern
  into the playfield tilemap.
- `$C7A4-$C7AC` are four-slot column blink state: one global timer, four per-slot timers, and four active/frame flags toggled between `1` and `2` before redrawing through `DrawColumnSprite`.
- `$C7AD` is `RESULT_RANK_POSITION`, written from `ResolveResultRankPosition` in `ProcessRoundResultAndEnterRoundEnd` and read by `DrawScoreRanking` plus the B-game round-end resume branch.
- `$C75D/$C75E/$C761/$C764/$C774` are the drop-input column swap animation state. `StartDropColumnSwapAnimation` stores the selected column and seeds two seven-entry cascade arrays; `AnimateDropping` advances them every two frames, blocks new drops while active, and clears `DROP_ANIM_ACTIVE` after swapping the selected `COLUMN_TOP_ROWS` bytes.
- The two `AnimateDropping` cascade passes now have behavior labels: `AnimateDropDownCascadeLoop` / `AdvanceDropDownCascadeSlot` process `DROP_ANIM_DOWN_STATES`, and `AnimateDropUpCascadeLoop` / `AdvanceDropUpCascadeSlot` process `DROP_ANIM_UP_STATES`.
- The late drop-up boundary redraw paths now name their left-column clear
  cutoff as `DROP_ANIM_UP_CLEAR_LEFT_MIN_DELTA`; both state-3 and final-state
  handlers use this same saved row-delta comparison before clearing the side
  column.
- The 2P round-transition slot-9 prelude now names the base-X offset, the two
  pre-loop frame values, and their send duration as
  `ROUND_TRANSITION_BASE_X_OFFSET`, `ROUND_TRANSITION_PRE_FRAME_0`,
  `ROUND_TRANSITION_PRE_FRAME_1`, and
  `ROUND_TRANSITION_PRE_FRAME_SEND_FRAMES`.
- `RunBoardScanTriggerSequence` now names the distance special case as
  `BOARD_SCAN_SINGLE_STEP_DISTANCE`: after incrementing the derived distance,
  this one-step case stages reward index zero, while larger distances store the
  distance directly in `BOARD_SCAN_REWARD_INDEX`.
- Sprite object type `$00` is now `SPRITE_OBJECT_TYPE_NONE`. `UpdateSprites`
  skips zero type bytes, the buffer initializer clears slot types to zero, and
  the round-transition reward tail clears slot 9 with this inactive type value.
- `InitDropCursorAnimationState` now names the drop-cursor inactive value as
  `DROP_CURSOR_ANIM_INACTIVE` when initializing `DROP_CURSOR_ANIM_ACTIVE`;
  the runtime stop path still clears the same byte through `xor a`.
- `AddPieceDisplayObjectToUiScratch` now compares the piece-display object
  tile/state byte against `PIECE_DISPLAY_FORCED_STATE` instead of raw `$07`
  before accumulating its count into `UI_SCRATCH`.
- `$FF8D` is now `UI_SCRATCH` rather than `TEXT_FADE`. Current consumers show
  it is a shared temporary byte, not a dedicated fade timer: piece-display
  occupancy counting, pre-play level text indexing, result-record leading-zero
  suppression, result rank/result-code staging, and link confirm panel tile
  alternation all reuse the same HRAM byte.
- The former `ProcessNewHighScore` entry is now
  `ProcessRoundResultAndEnterRoundEnd`. Its callers pass round-result codes
  from B-type clear, single-player game-over, queued 2P results, and link
  result handling; the routine resolves rank/result state, selects the result
  sound path, seeds `ROUND_END_WAIT_TIMER`, and enters `GAME_STATE_ROUND_END`.
  The B-type clear tail is now `ProcessBTypeClearRoundResult`, and the internal
  result branches are `Finish2PRoundResult` / `HandleSinglePlayerRoundResult`.
- `InitPieceDisplaySlotOrder` now names the initial order entries as
  `PIECE_DISPLAY_SLOT_INDEX_0..3`, matching the four slot indices later
  shuffled and consumed by `BuildPieceDisplayStatesForCount`.
- The drop-animation completion path is now named through its column-swap
  behavior: `FinishDropCascadeAndSwapColumns` calls `UpdateDropPositions`,
  `SwapDropAnimationColumnCellsLoop` swaps seven two-byte-spaced visible cells
  between adjacent columns, and `SwapColumnTopRowsAfterDrop` swaps the selected
  `COLUMN_TOP_ROWS` entry with its neighbor before clearing the active flag.
- The one-byte `pop hl` after `ClearLandedGameplayObject` is now labeled
  `UnreachedClearLandedGameplayObjectPop`. `ClearLandedGameplayObject` always
  jumps to `ClearCurrentGameplaySpriteObjectRecord`, while the preceding
  game-over/result paths return before this byte, so no current control-flow
  edge reaches it.
- Bank 0 drop collision/update locals are now named by behavior:
  `ScanDropCollisionSpriteSlotsLoop` scans active gameplay object slots,
  `ReturnDropCollisionDetected` returns carry when `CheckDropSpriteOverlap` finds
  a collision, and `UpdateDropPositionsLoop` derives missing grid-column bytes
  from sprite base X before the final column swap.
- Drop collision now names the grid-column invalidation and overlap constants:
  a collision shifts `SPRITE_OBJECT_BASE_X` by `DROP_COLLISION_SPRITE_X_STEP`,
  marks `SPRITE_OBJECT_GRID_COLUMN` as `SPRITE_OBJECT_GRID_COLUMN_UNSET`, and
  lets `UpdateDropPositionsLoop` recompute the column from base X. The row
  overlap test uses `DROP_COLLISION_Y_OVERLAP_LIMIT`.
- Bank 0 drop down/up state locals are now named by branch role inside
  `AnimateDropDown` and `AnimateDropUp`, including the state-2/state-3 checks,
  final-state handlers, boundary redraw labels, `ClearDropAnimationStateLoop`,
  and `ReturnFromStartDropColumnSwapAnimation`.
- Bank 0 `00:$09C8` is a coherent but currently unreferenced board-fill
  fragment. It is labeled `UnusedFillBoardDataPattern`; its local loops clear a
  shrinking span under `BOARD_DATA`, write a growing column-index span, and
  store a tail byte derived from
  `UNUSED_BOARD_PATTERN_TAIL_BASE - column * 2`.
- Bank 0 `UpdateColumnBlinkState` now has behavior labels for its slot scan:
  `BeginColumnBlinkSlotScan`, `ColumnBlinkSlotLoop`,
  `TickColumnBlinkSlotTimer`, `ToggleColumnBlinkSlotFrame`,
  `DrawColumnBlinkSlot`, and `AdvanceColumnBlinkSlot`.
- `$C66A-$C66D` are `COLUMN_TOP_ROWS`, a four-byte per-column row/fall-target array. `SeedColumnTopRows` seeds all four entries from `COLUMN_TOP_ROW_SEED`, `GetSelectedColumnTopRow` indexes it by `FALLING_PIECE_GRID_COLUMN`, `DrawColumnSprite` uses it for column blink drawing, and `AnimateDropping` swaps adjacent entries after a drop-input cascade.
- The selected-column falling-piece helper group is now behavior-named: `GetSelectedColumnTopRow` returns the current selected-column row and leaves `HL` on the `COLUMN_TOP_ROWS` entry; `StagePiecePayloadInSelectedColumn` decrements `PIECE_DISPLAY_REMAINING`, writes the staged tile/piece payload one `BOARD_ADJACENT_VISIBLE_CELL_DELTA` step before the selected column/row cell, and leaves the compared existing cell in `B`; `ClearCurrentGameplaySpriteObjectRecord` clears the 10-byte gameplay object record selected by `SPRITE_OBJECT_STAGING_INDEX`.
- `FindBoardScanTargetRow` now names the scan helper that starts at `PIECE_FALL_POS`, probes the selected 16-byte board column every two row offsets via `ReadBoardCellAtColumnRow`, and returns the row offset only when it finds `BOARD_SCAN_TARGET_PAYLOAD`; otherwise it returns zero for the landing path.
- `FinishBoardScanNoTargetLanding` now names the `RunBoardScanTriggerSequence` no-target exit:
  it spawns the land field-column effect, clears the current gameplay object,
  plays `SND_PIECE_LAND`, discards the scan return, and exits the falling-piece
  update without staging the trigger payload into `BOARD_DATA`.
- Bank 1 sound command dispatch is now separated from anonymous jump labels. `DispatchSoundNonEndCommand` starts the non-`$FF` parser path, `CheckSoundLoopJumpCommand` handles the `$FE` loop/jump branch, `CheckSoundLengthEnvelopeCommand` covers the `$D0-$DF` length/envelope branch, and `CheckSoundExtendedCommand` enters the `$E8+` extended command checks. Pitch-slide setup/update is now labeled `InitSoundPitchSlideForNote`, `UpdateSoundPitchSlide`, `UpdateSoundPitchSlideDescending`, and `ClearSoundPitchSlideFlags`.
- A small Bank 0 local-label cleanup removed more anonymous jump labels without broad semantic guesses: `CopyOAMDMARoutineToHRAMLoop`, `StoreDisabledLCDCAndRestoreIE`, `CheckPauseAllowedForLinkMaster`, `CheckPersistMagicByte1`, `ClearColumnLeftNextTilemapPage`, `UpdateFieldAnimSlot11BaseY`, and `HandleSinglePlayerRoundCompleteFlow`.
- The final anonymous `Jump_*` labels in Bank 0/1 real code are now gone. `ResetJoypadStateAndReinitOnRelease` clears `JOYPAD_HELD`, waits for the raw joypad lines to recover, and jumps back to `Init`; `MultiplyAddCarryChain` names the internal carry-propagation portion of `MultiplyAddStep`; `ExpandSoundIndexChannelEntryLoop` walks the selected sound-index entry's channel records before `StartSoundSequence`.
- Bank 0 `Multiply` now has internal branch labels and HRAM names for the
  shift/add random update loop: `RNG_STATE` (`$FFBB-$FFBE`), `RNG_WORK`
  (`$FFBF-$FFC2`), and `RNG_MULTIPLIER_LOW_WORK` (`$FFC3`) pair with
  `RNG_MULTIPLIER_HIGH_WORD`, `RNG_MULTIPLIER_LOW_BYTE`, and
  `RNG_INCREMENT_BYTE_0..3`. `MultiplyShiftMultiplierLoop`,
  `AddShiftedMultiplicandToProduct`, and `ShiftMultiplicandForNextBit` describe
  the local arithmetic structure; callers use the returned byte for piece
  display selection, shuffles, preplay/menu timing, and result setup.
- Bank 0 game-state setup locals now distinguish the source of active settings:
  `InitSinglePlayerLevelSpeedSettings` copies 1P option values, while
  `InitTwoPlayerLevelSpeedSettings` forces `GAME_TYPE` `$01` and copies the
  negotiated link level/speed. `UpdateDropCursorAnimation` drop-cursor locals now name the
  alternate-frame advance, frame store, and active-flag clear points.
- The result-record ranking and rendering path is now named by behavior. `CopyATypeEggCountRemainingDigits` / `CopyBTypeResultTimerDigits` stage the mode-specific detail digits, `MaskCurrentResultRecordDigits` low-nibble-normalizes the `RESULT_RECORD_SIZE` staged record with `RESULT_RECORD_DIGIT_MASK`, `ScanResultRecordInsertPositionLoop` compares `CURRENT_RESULT_RECORD` against `RESULT_RECORD_ROW_COUNT` stored records starting from `RESULT_RECORD_FIRST_RANK`, `CompareBTypeResultTimerDigits` handles the B-type lower-time-is-better detail comparison, `InsertCurrentResultRecordAtRank` shifts lower records down when needed and uses `RESULT_RECORD_FIRST_RANK` for the extra top-row shift, `CopyCurrentResultRecordToRankSlot` stores the staged record, and `SetupResultRecordScreen` loads the Bank 3 result tiles before building the record table. `InitResultRecordsIfNeeded` seeds empty record heads with `RESULT_RECORD_EMPTY_HEAD`. `DrawStoredResultRecords` then renders the stored record digits through `DrawResultRecordDigitRun`, which applies `RESULT_RECORD_DIGIT_MASK`, adds `RESULT_RECORD_DIGIT_TILE_BASE`, suppresses leading zeroes according to `RESULT_RECORD_SUPPRESS_LEADING_ZEROES`, and keeps the second B-type timer pair unsuppressed after `RESULT_RECORD_TIMER_SEPARATOR_TILE`. `WaitResultRecordScreenInput` fades in the named `RESULT_RECORD_PALETTE_FADE_VALUE_0..3` palette sequence emitted as `RESULT_RECORD_PALETTE_FADE_STEP` records with `RESULT_RECORD_PALETTE_FADE_STEP_COUNT` / `RESULT_RECORD_PALETTE_FADE_WAIT_FRAMES` and blinks the inserted row label until input.
- `InitResultRecordsIfNeeded` now names its one-time record-head initialization labels:
  `InitATypeResultRecord0..2` and `InitBTypeResultRecords`.
- `$C66F/$C670` are `DROP_CURSOR_ANIM_ACTIVE` and `DROP_CURSOR_FRAME_TIMER`,
  controlling the short slot-0 cursor frame animation after a drop input is
  accepted. The accepted-input path now names
  `DROP_CURSOR_ANIM_ACTIVE_VALUE`, and the fall timer hold during drop/cursor
  animation is `PIECE_FALL_TIMER_ANIM_HOLD_RELOAD`.
- Bank 0 `00:$22CC-$230E` and `00:$230F-$234B` are field animation delta tables. `StepFieldAnimSlot11SideDelta` / `StepFieldAnimSlot10SideDelta` index `FieldSideDeltaTable`, while `StepFieldAnimSlot13RowDelta` / `StepFieldAnimSlot12RowDelta` index `FieldRowDeltaTable`; both tables now use `FIELD_ANIM_DELTA_PAIR` records made from `FIELD_ANIM_DELTA_POSITIVE`, `FIELD_ANIM_DELTA_ZERO`, and `FIELD_ANIM_DELTA_NEGATIVE` entries, then terminate with `FIELD_ANIM_END_SENTINEL` (`$10`).
- WRAM `$C6C3-$C6C6` now names the per-slot field animation cursors for logical sprite object slots 11, 10, 13, and 12. `$C6C7-$C6CA` now names the matching active flags, in slot order 12, 11, 10, and 13.
- `SetupMultiplayer` is now `UpdateFieldAnimationSlots`, matching its only
  confirmed behavior: dispatching the four `UpdateFieldAnimSlot*` routines
  while their active flags are nonzero.
- `UpdateFieldTimers` is called from both Bank 1 `RunGameplayFrame` and Bank 0 `Send2PData`, decrementing `FIELD_COLUMN_TIMERS` at `$C6CB-$C6CE` and clearing logical sprite object slots 10-13 when each timer expires.
- Bank 1 `01:$4570` is now labeled `AdvanceATypeLevelDisplayDigits`; title/input code calls it before `DrawLevelDisplayDigits` to advance the shared level display digits. The title/preplay redraw path now uses `TITLE_LEVEL_PREVIEW_DIGITS_COORD`, an alias of the A-type playfield level digit coordinate, instead of the raw packed `$0812` coordinate.
- Bank 1 elapsed-timer helpers are now named by behavior: `DrawRoundTimerDigits` renders the round timer from `ROUND_TIMER_DIGITS`, `ClearRoundTimerDigitsAndResume` clears the four round-timer display digits and `ROUND_TIMER_STOPPED`, and `ClearTotalTimerDigitsAndResume` does the same for `TOTAL_TIMER_DIGITS` / `TOTAL_TIMER_STOPPED`.
- `TickElapsedTimerDigits` now names its digit bounds directly: the frame divider is `ELAPSED_TIMER_FRAMES_PER_SECOND` (`$3C`), normal decimal digits use `ELAPSED_TIMER_DECIMAL_DIGIT_LIMIT`, the seconds-tens digit rolls at `ELAPSED_TIMER_SECONDS_TENS_LIMIT` (`6`), and overflow clamps both elapsed timers to 99:59 through `ELAPSED_TIMER_MAX_ONES` / `ELAPSED_TIMER_MAX_SECONDS_TENS`.
- Bank 1 playfield HUD helpers are now named by behavior: `DrawPlayfieldLevelDigits`, `DrawPlayfieldSpeedValue`, and `DrawPlayfieldEggDisplay` choose mode-specific tilemap coordinates before drawing level digits, active-speed tiles, and the egg text/count display. `DrawEggTextFrame0` is the frame-0 wrapper around `DrawEggTextFrameByIndex`.
- Egg-text animation frame constants now name the `DrawEggTextFrameByIndex` frame 1/2
  pulse, the `EGG_TEXT_FRAME_TOGGLE_MASK`, and the alternate animation active
  value / phase toggle mask.
- The playfield HUD coordinate-selection locals now name the 2P, A-type, and B-type branches directly. `PLAYFIELD_LEVEL_DIGITS_*_COORD`, `PLAYFIELD_SPEED_VALUE_*_COORD`, and `PLAYFIELD_EGG_DISPLAY_*_COORD` capture the packed row/column destinations; `DrawLevelDisplayDigitsAtPlayfieldCoord`, `DrawSpeedValueAtPlayfieldCoord`, and `DrawEggDisplayAtPlayfieldCoord` are the shared draw targets.
- Level-display rollover now uses `LEVEL_DISPLAY_DIGIT_LIMIT` /
  `LEVEL_DISPLAY_MAX_DIGIT`, and `DrawPlayfieldEggCountDigits` uses the explicit
  `PLAYFIELD_EGG_COUNT_A_TYPE_COORD` / `PLAYFIELD_EGG_COUNT_B_TYPE_COORD`
  destinations instead of raw packed row/column values.
- The orphaned Bank 1 fragment between `DrawPlayfieldRoundTimerDigits` and `DrawTwoPlayerPlayfieldRoleHeaders` is labeled `UnusedDrawPlayfieldGameTypeHeader`. It draws a 1P-only A/B-type header from row 1/column 16, but the current static scan finds no caller/entry label reaching it.
- `Yoshi/yoshi.sym` now matches the recovered Bank 1 egg text animation labels at `01:$4A21`, `01:$4A31`, `01:$4A66`, and `01:$4A7B`: `StartEggTextPulse`, `UpdateEggTextAnimation`, `ToggleEggTextAltAnimation`, and `EnableEggTextAltAnimation`.
- Bank 1 playfield timer/link header helpers are now named by behavior: `DrawBTypeTimerHeaderAndDigits` draws the 1P B-TYPE timer header before `DrawPlayfieldRoundTimerDigits`, and `DrawTwoPlayerPlayfieldRoleHeaders` draws the two 2P role header rows with tile rows `$70/$74` swapped when `LINK_ROLE` is `LINK_ROLE_SLAVE`.
- Bank 1 playfield side-panel layout helpers are now named by behavior. `UpdateNextDisplay` fills the 4x18 side panel at row 0/column 16, then `Draw1PPlayfieldSidePanelLabelRow0`, `DrawPlayfieldSidePanelLabelRow1`, `DrawPlayfieldBottomColumnMarkers`, and the three `Blank*PlayfieldSidePanelRows` helpers layer mode-specific labels, column markers, and blank rows.
- Bank 0 `HandlePlayfieldInput` now names the frame input helper by its actual role: cursor left/right movement, A/B drop-start acceptance, and Down-held fast-fall clamping. The falling-piece motion/landing update now lives in `UpdateFallingPieceMotionAndLanding`.
- Bank 0 `GetLevelFallDelay` now names the helper that caps `PROGRESSION_LEVEL` and indexes `LevelFallDelayTable`; it does not itself process falling. `DecrementPieceDisplayRemaining` now names the one-byte helper that decrements `PIECE_DISPLAY_REMAINING`.
- Bank 0 playfield setup helpers are now named by behavior: `InitPlayfieldBoardAndPieceState` is the setup routine called by Bank 1 playfield init paths, `ClearPieceSpriteObjectSlots` clears logical sprite slots 1-8, `ClearBoardData` clears the full `$40`-byte board storage, `InitATypeGameTurnPieceDisplay` wraps the A-type game-turn piece-display initialization, `ClearRoundLandingAndResultState` resets result/landing staging bytes, `InitBTypeFallTimingAndBoardSeed` sets B-type fall delay and the board seed, and `FillInitialBoardColumns` performs the seeded initial board fill behind the VBlank wait wrapper.
- `PIECE_SPRITE_OBJECT_SLOT_COUNT` / `PIECE_SPRITE_OBJECT_CLEAR_BYTES` now
  name the slot 1-8 clear span used by `ClearPieceSpriteObjectSlots`.
- `SPRITE_OBJECT_SCAN_END_OFFSET` now names the low-byte wrap value used by
  `UpdateSprites` after scanning the 16 logical sprite object slots on the
  `$C2xx` page.
- The Bank 1 coordinate-based tilemap helpers are now named by behavior. `FillTilemapRectByCoord` converts a packed row/column coordinate through `CalcTilemapAddress` and fills a `B` by `C` rectangle with tile `A`; `DrawSequentialTileRowByCoord` converts the coordinate and writes `B` consecutive tile IDs starting at `C`.
- Their local loops are also named: `FillTilemapRectRowLoop`,
  `FillTilemapRectColumnLoop`, `AdvanceTilemapRectRow`, and
  `DrawSequentialTileRowLoop`. `StartNextRound` now has named branches for the
  1P level/BGM setup path and the shared next-round setup tail.
- Bank 1 game BG setup now names the top-row fill coordinate/width/tile, the
  field-column tile pattern record size/count/index shift/destination, and the
  single-player next-round `ACTIVE_LEVEL_MAX` clamp.
- HRAM `$FF80` is now named `OAM_DMA_HRAM`; `SetupOAMDMA` copies the DMA routine there and `VBlankHandler` calls it. The ROM copy of the routine is now restored as code: it writes `SHADOW_OAM_HI` to `rDMA`, waits `OAM_DMA_WAIT_LOOP_COUNT` decrements, then returns.
- Bank 0 initial utility loops are now named by direct behavior:
  `WaitJoypadLinesReleasedLoop` polls raw P1 lines after clearing
  `JOYPAD_HELD`, `WaitForLCDOffSafeLine` waits for `rLY == $91` before
  disabling LCD, `ClearShadowOamLoop` clears all `$A0` shadow-OAM bytes,
  `HideShadowOamSpritesLoop` writes hidden Y to each OAM entry, and
  `CopyBytesDuplicatedLoop` duplicates each source byte to two destination
  bytes.
- The same low-level utility path now uses hardware/utility constants for the
  raw P1 and LCD/OAM DMA immediates: `P1F_GET_DPAD`, `P1F_GET_BTN`,
  `P1F_GET_NONE`, `P1_INPUT_BITS_MASK`, `P1_INPUT_BITS_RELEASED`,
  `OAM_DMA_HRAM_LOW`, `OAM_DMA_ROUTINE_SIZE`, `OAM_DMA_WAIT_LOOP_COUNT`,
  `LCD_OFF_SAFE_SCANLINE`, and `LCDC_DISABLE_MASK`.
- Bank 1 `CheckJoypadRaw` now reuses the same P1 constants when polling
  button lines directly during VBlank-side joypad checks.
- The queued VRAM-copy setup now names its per-VBlank chunk cap:
  `VRAM_COPY_MAX_BLOCKS_PER_VBLANK` is used by both the live primary queue and
  the unreachable secondary setup-shaped fragment.
- Startup hardware initialization now names the remaining clear initialization
  immediates: default DMG palettes, `STACK_TOP`, `HRAM_WORK_CLEAR_SIZE`,
  `STARTUP_ENABLED_INTERRUPTS`, `WY_OFFSCREEN_Y`, `WX_LEFT_EDGE`, `SCRN0_HI`,
  `SCRN1_HI`, `HARDWARE_TILEMAP_CLEAR_TILE`, `HARDWARE_TILEMAP_SIZE`,
  `TITLE_INIT_LCDC_FLAGS`, and the final `GAME_LCDC_FLAGS`.
- Bank 0 startup clear loops are now named by behavior:
  `UseFullWRAMClear` marks the result-record magic as invalid, `BeginWRAMClear`
  initializes the `$C000-$DFFF` clear, `ClearWRAMLoop` preserves
  `$C709-$C75A` only when startup selected
  `WRAM_CLEAR_MODE_PRESERVE_RESULT_RECORDS`; `UseFullWRAMClear` selects
  `WRAM_CLEAR_MODE_FULL`, `ClearWRAMByte` performs the byte store,
  `ClearVRAMLoop` clears `_VRAM`, and `ClearHRAMWorkAreaLoop` clears
  `$FF80-$FFFE` before `SetupOAMDMA` reinstalls the DMA routine.
- Bank 0 tilemap fill loops are now named by direct destination:
  `BeginBgMapShadowFill` / `FillBgMapShadowLoop` fill `BG_MAP_SHADOW`, while
  `BeginHardwareTilemapFill` / `FillHardwareTilemapLoop` fill one `$400`-byte
  hardware tilemap page selected by `H`.
- `FillGameTilemap` and `FillTitleTilemap` now name their full
  `BG_MAP_SHADOW` fill tiles as `GAME_BG_SHADOW_CLEAR_TILE` and
  `TITLE_BG_SHADOW_CLEAR_TILE`. The game fill tile aliases
  `FIELD_OCCUPANCY_EMPTY_TILE`, matching the later field-count scans that
  ignore `$4A` entries.
- Bank 2 graphics copy sizes are now named at their Bank 0 load sites:
  `BANK2_GAME_TILE_SET_COPY_SIZE`, `BANK2_TITLE_TILE_SET_COPY_SIZE`,
  `BANK2_COMMON_TILE_SET_COPY_SIZE`,
  `BANK2_PREPLAY_MENU_OVERLAY_COPY_SIZE`,
  `BANK2_TWO_PLAYER_SHARED_TILES_COPY_SIZE`, and
  `BANK2_TWO_PLAYER_NONMASTER_TILES_COPY_SIZE`.
- The Bank 2 pre-play and 2P ranges now use load-role names instead of
  numbered/generic labels. `PreplayMenuOverlayTiles` is copied only during
  `GAME_STATE_PREPLAY_INIT`; `TwoPlayerSharedTiles` is copied for every 2P
  gameplay load; `TwoPlayerNonMasterTiles` is copied only when
  `LINK_ROLE != LINK_ROLE_MASTER`.
- Bank 2's unloaded tail is now explicit as `Bank2UnusedTailTileData`
  (`02:$73D0-$7FFF`). The confirmed Bank 2 load paths stop at
  `TwoPlayerSharedTiles` (`02:$71D0-$73CF`), no current source reference targets
  the tail label, and the rendered sheet is mostly noise/padding-like data.
- Bank 3 matching/result-record copy sizes are now named at their load sites:
  `BANK3_MATCHING_TILE_BLOCK_COPY_SIZE` for the three `ProcessMatching`
  tile-block copies and `BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE` for the two
  `SetupResultRecordScreen` copies.
- Bank 0 `CalcTilemapAddress` now has named carry-continuation labels:
  `AddTilemapColumnOffset`, `AddBgMapShadowBaseLow`, and
  `StoreCalculatedTilemapAddressLow`, matching the formula
  `BG_MAP_SHADOW + row * BG_MAP_ROW_STRIDE + column`.
- Bank 0 MainLoop state dispatch branches are now named by the state they
  test next (`DispatchTitleMenuState` through `DispatchPreplayInitState`);
  setup-local branches now distinguish 1P BGM start from 2P settings
  application and the shared `InitPlayfieldAfterBgmSetup` tail. The final
  out-of-range state fallthrough is now `IgnoreInvalidGameStateAndLoop`.
- Bank 0 pause locals are now named by behavior: `CheckPauseButtonInput`,
  `WaitPauseResumeInputLoop`, `PlayPauseSoundAndHalt`, and
  `WaitLinkPeerUnpauseLoop`.
- Pause/link wait flag stores now name their active `$01` values:
  `PAUSE_FLAG_ACTIVE`, `SOUND_PAUSE_FLAG_ACTIVE`, and
  `LINK_SEND_DROP_INPUT_LOCK_ACTIVE`; clear paths still use `xor a`.
- Bank 0 `MultiplyAndCount` now exposes `CountMaskedMultiplyBitsLoop` and
  `ContinueMaskedMultiplyBitCount`, matching its observed use as a masked
  random set-bit counter for piece display shuffles.
- The shared piece-display shuffle selector now names mask `$38` as
  `PIECE_DISPLAY_SHUFFLE_INDEX_MASK`. `MultiplyAndCount` counts the masked
  result bits, so both slot-order and code-pool shuffles currently select
  indices `0..3`.
- Initial B-type board fill now names its generated-code source as
  `PIECE_DISPLAY_CODE_POOL + INITIAL_BOARD_PIECE_POOL_OFFSET` after three
  shuffles. `AvoidInitialBoardAdjacentDuplicate` compares the candidate with the already-filled cell
  two bytes ahead, increments on equality, and wraps only when the
  post-increment value reaches `INITIAL_BOARD_PIECE_WRAP_SENTINEL`.
- `UpdatePieceDisplayBlink` now names its display-object scan shape: it walks
  `PIECE_DISPLAY_BLINK_SLOT_COUNT` slots from `SPRITE_OBJECT_SLOT_1`, only
  toggles active `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` records, XORs
  `PIECE_DISPLAY_BLINK_FRAME_TOGGLE_MASK` into the frame byte, and skips both
  `PIECE_DISPLAY_FORCED_STATE` and `PIECE_DISPLAY_BLINK_EXEMPT_STATE`.
- Bank 0 `UpdateSpriteObject` now names the wait-phase and writeback locals:
  `TickSpriteObjectWaitPhase` decrements/reloads the staged object delay and
  advances phase `$01` to `$02`, and `WriteBackSpriteObjectStaging` copies the
  updated staged record back to the selected `$C2xx` slot.
- Bank 0 board/tile sprite drawing locals are now named by behavior:
  `CopyEncodedTilePatternRow4SkipFF` exposes the conditional byte-advance labels,
  `DrawGridPieceWithinBounds` / `DrawGridPieceSecondRow` cover the two-row
  tile write, and `DrawAllColumnsColumnLoop` / `DrawAllColumnsRowLoop` render
  the seven visible entries for each of the four board columns.
- The board draw and drop-cascade stride code now reuses the existing geometry
  constants: `BOARD_CELL_STRIDE` for two-byte board row stepping,
  `GRID_PIECE_TILE_WIDTH` for visible column stepping,
  `DROP_ANIM_STATE_STRIDE` for the drop cascade arrays, and
  `COLUMN_SPRITE_TOP_ROW_OFFSET` for the three-row column-sprite start offset.
- The board/tile pattern tables now have consumer-specific names.
  `GridPiecePatternTable` is indexed by `GetGridPiecePatternOffset` with an
  8-byte stride and copied directly by `CopyTilePatternRow4`; its nine records
  are labeled as `GridPiecePatternEmptyPayload`,
  `GridPiecePatternPiece1..6`, `GridPiecePatternScanTrigger`, and
  `GridPiecePatternScanTarget`. `BOARD_PAYLOAD_EMPTY`, `BOARD_PAYLOAD_PIECE_1..6`,
  `BOARD_PAYLOAD_SCAN_TRIGGER`, and `BOARD_PAYLOAD_SCAN_TARGET` now document
  the visible board payload range. The table bytes now use
  `GRID_PIECE_PATTERN_ROW` records and `GRID_PIECE_PATTERN_*_TILE` constants
  scoped to 4x2 record position and payload role: normal piece records share
  the four frame-corner tiles, and the scan records use blank outer columns
  with their own inner tile pairs.
- The `SelectPieceDisplayCode` return tails now use explicit
  `PIECE_DISPLAY_CODE_1`, `PIECE_DISPLAY_CODE_2`, `PIECE_DISPLAY_CODE_3`,
  `PIECE_DISPLAY_CODE_4`, and `PIECE_DISPLAY_CODE_8` constants. This keeps the
  menu/display return values separate from board-scan trigger/target names that
  happen to share nearby numeric values.
- `SelectPieceDisplayCode` now also names the B-type timer/occupancy gates and
  the random branch thresholds used after `Multiply`. These constants are scoped
  to return-code boundaries rather than inferred user-visible probabilities.
- `ColumnSpritePatternTable` is split into the two `$30`-byte frame blocks used
  by `COLUMN_BLINK_FRAME_2` and `COLUMN_BLINK_FRAME_1`, then a separate
  `UnreachedColumnSpritePatternTailRows` 16-byte tail. The normal column-blink
  path indexes only the two frame blocks through `GetColumnSpritePatternOffset`
  with a 12-byte stride and copies rows through
  `CopyEncodedTilePatternRow4SkipFF`.
- The live `ColumnSpritePatternTable` rows now use
  `COLUMN_SPRITE_PATTERN_ROW` records and
  `COLUMN_SPRITE_PATTERN_*_ENCODED_TILE` constants. These names are explicitly
  encoded source bytes because `CopyEncodedTilePatternRow4SkipFF` increments
  each non-`$FF` byte before writing the BG-map tile.
- `UnreachedColumnSpritePatternTailRows` now uses scoped
  `COLUMN_SPRITE_PATTERN_ROW` records and
  `UNREACHED_COLUMN_SPRITE_TAIL_*_TILE` constants for its four raw rows. The
  names stay separate from live encoded column-sprite constants because no
  confirmed path indexes the tail.
- Bank 0 `DrawColumnSprite` now names its column-top-row read and row-copy
  tails: `ReadColumnTopRowForSprite`, `DrawColumnSpriteRow0`,
  `DrawColumnSpriteRow1`, and `DrawColumnSpriteRow2`. The small alternate
  fragment is now labeled `UnreachedColumnSpriteAlternateRowFragment` because
  the preceding unconditional branch skips it on the live path; its wrap check
  now uses the existing `COLUMN_TOP_ROW_OVERFLOW_SENTINEL`.
- Bank 0 `FillRect` and the gameplay object update/display hub now have labels
  for their immediate behavior: `FillRectRowLoop`, `FillRectColumnLoop`,
  `UpdateGameplayObjectsAndCheckBTypeClear`, `UpdateGameplayObjectSlotsLoop`,
  `CheckBTypeColumnClearLoop`, `TickFallTimerForActiveGameplayObjects`,
  `UpdatePieceFallTimer`, `ReloadPieceFallTimer`,
  `UpdatePieceDisplayByGameType`, `RunBTypePieceDisplayUpdate`,
  `CheckGameplayObjectSlotsActive`, `ScanGameplayObjectSlotsLoop`, and the
  fall-acceleration reload branches in `UpdateFallAcceleration`. The top-level
  gameplay object update loop now uses `SPRITE_OBJECT_ACTIVE_SLOT_COUNT` for the
  four active piece slots, and the active-slot scan now returns the named
  `GAMEPLAY_OBJECTS_ACTIVE` value.
- The 2P B-type clear path inside `UpdateGameplayObjectsAndCheckBTypeClear`
  intentionally unwinds out of the regular `RunGameplayFrame` tail. After
  queueing `ROUND_RESULT_CODE_NONZERO`, it reaches the shared
  `ProcessBTypeClearRoundResult` tail with the saved AF already popped, so
  the next `pop af` discards the `RunGameplayFrame` return address before
  `ProcessRoundResultAndEnterRoundEnd` enters `GAME_STATE_ROUND_END`.
- Bank 0 `HandlePlayfieldInput` now exposes its frame-input branches:
  `CheckDropStartInput`, `HandleCursorMoveOrFastFall`,
  `MovePlayerCursorRight`, `MovePlayerCursorLeft`,
  `CheckFastFallActiveSlots`, `ClampFastFallTimers`,
  `ClampGameplayObjectFastFallTimers`, `ClampGameplayObjectFastFallLoop`, and
  `AdvanceFastFallClampSlot`.
- Bank 0 `UpdateFallingPieceMotionAndLanding` now exposes its fall/landing locals:
  `AdvanceFallingPiecePosition`, `HandleFallingPieceReachedColumn`,
  `DrawLandedPieceAndUpdateColumnTop`, `ProcessSinglePlayerGameOverResult`,
  `ClearLandedGameplayObject`, and `ClearGameplayObjectRecordLoop`. The
  selected-column helpers now also have carry/loop tails named by behavior,
  including `ReadSelectedColumnTopRowEntry`,
  `StoreStagedPayloadInBoardColumn`, `ClearPieceSpriteObjectSlotsLoop`,
  `ReadArrayElementAtOffset`, `LoadUnhalvedBTypeFallDelay`,
  `InitBTypeBoardSeed`, and the initial fall-acceleration timer branches.
- `UpdateFallingPieceMotionAndLanding` now uses narrow constants for its active return and row
  movement evidence: `SPRITE_OBJECT_UPDATE_CONTINUE` is the nonzero return that
  causes `UpdateSpriteObject` to write the staged record back,
  `PIECE_FALL_SPRITE_Y_STEP` is the 8-pixel Y advance while a piece is still
  falling, `BOARD_DRAW_FIRST_ROW` is the top-row game-over sequence check, and
  `COLUMN_TOP_ROW_OVERFLOW_SENTINEL` is the `$FF` top-row underflow that enters
  the game-over/result path.
- The active architecture overview is now aligned with recovered labels and
  data shape. Stale placeholders such as `ProcessGameTurn`, `CheckMatch`,
  `DisplayScore`, `MusicDataInit`, and `ProcessFieldLogic` were replaced with
  the current gameplay, board, drawing, VBlank, and sound labels; its board
  layout now matches the four 16-byte `BOARD_DATA` column blocks with odd-byte
  visible payload cells.
- Landing and board-scan paths now reuse `BOARD_CELL_STRIDE` for general direct
  two-byte row movements and `BOARD_ADJACENT_VISIBLE_CELL_DELTA` for adjacent
  visible-cell movements instead of carrying local `inc`/`dec` pairs. The same
  cleanup names the level fall-delay table clamp as
  `LEVEL_FALL_DELAY_TABLE_COUNT` / `LEVEL_FALL_DELAY_MAX_INDEX`, the board-scan
  loop seed and BG refresh row as `BOARD_SCAN_STEP_INITIAL` /
  `BOARD_SCAN_BG_REFRESH_ROW`, the round reset timer seed as
  `UNRESOLVED_LANDING_RESET_TIMER_INITIAL`, and the field-column object frame
  arguments as `FIELD_COLUMN_EFFECT_FRAME_COMMIT` and
  `FIELD_COLUMN_EFFECT_FRAME_LAND`.
- Bank 1 player cursor and round-complete sprite frame records now use
  consumer-specific tile/layout labels. `SpriteFrameTable_PlayerCursor` uses
  five distinct `SpriteTileList_PlayerCursorFrame*` records and three
  `SpriteLayout_PlayerCursor*` layouts, while
  `SpriteFrameTable_RoundCompleteTile` uses the shared
  `SpriteTileList_RoundCompleteTile` with four flip-specific layouts.
- Bank 1 settings cursor and round-transition sprite frame records also now
  use consumer-specific labels. The settings cursor alternates between normal
  and `Alt` tile lists while sharing `SpriteLayout_TwoTileRow`; the
  round-transition table names its normal/alternate frame tile lists and its
  two/four/six/eight-sprite layouts by emitted hardware sprite count.
- Bank 1 piece-display sprite frame records now use frame-index tile-list
  labels and `SpriteLayout_PieceDisplayTwoTileRow`. The former
  `GameOverPiece` wording was too narrow because `SpriteUpdatePointerTable`
  dispatches `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` to this frame table, and the
  same object type is built by both active piece-display and game-over/display
  paths.
- Bank 1 `SpriteLayout_*` payloads now use `SPRITE_LAYOUT_ENTRY y_delta,
  x_delta, attr` records instead of raw three-byte `db` rows. Attribute
  expressions name the local end/inherit control bits alongside the hardware
  OAM flip/palette bits, while overlapping labels such as
  `SpriteLayout_FieldColumnEffectUpper` and `SpriteLayout_TwoTileRow` preserve
  the original pointer targets.
- Bank 1 `SpriteUpdatePointerTable` now uses `SPRITE_OBJECT_FRAME_TABLE`
  records to show the object type associated with each frame table. The
  `SpriteTileList_*` payloads now use count-specific `SPRITE_TILE_LIST_N`
  macros for the 36 explicit tile-id byte streams; the
  `SpriteTileList_PieceDisplayFrame22` alias still intentionally shares the
  first two bytes of `SpriteLayout_TwoTileRow`, preserving the original address
  reuse.
- The last raw immediate `PlaySound` IDs in `InitTwoPlayerPreplayScreen` are now
  classified as `SND_2P_PREPLAY_MASTER_INIT` (`$6B`) and
  `SND_2P_PREPLAY_SLAVE_INIT` (`$6D`), with matching sound-index aliases. The
  role split is controlled by `LINK_ROLE_SLAVE`.
- Bank 1 countdown/playfield digit drawing now names the 1P countdown tile-slot
  A/B coordinates, four alternating countdown tile IDs, countdown blit timer
  reload, playfield digit mask/base, blank digit tile, and round-timer
  separator tile.
- Bank 1 score handling now names the five display digits, the
  `ResetScoreAccumulatorAndDigits` clear span (`SCORE_CLEAR_BYTE_COUNT`), and the BCD overflow
  cap constants used by `AddScore` to saturate at `99999`.
- Bank 0 board/piece setup locals now expose the remaining setup loops:
  `ClearBoardDataLoop`, `SeedColumnTopRowsLoop`,
  `InitPieceDisplayCodePoolLoop`, `WaitInitialBoardFillVBlankLoop`,
  `FillInitialBoardColumnLoop`, `FillInitialBoardCellLoop`,
  `ReturnInitialBoardPieceCandidate`, `ReturnIncrementedInitialBoardPiece`,
  `InitBTypePlayfieldBoardAndDisplay`, `SetPlayfieldCursorSlotType`, and
  `ReadLevelFallDelayTable`.
- Bank 0 `RunBoardScanTriggerSequence`, `FindBoardScanTargetRow`, and
  `ReadBoardCellAtColumnRow` locals now name the board-scan animation loop,
  scan-step send wait, target-row search/return paths, and computed board-cell
  address carry tails.
- Grid-piece rendering now has narrow constants. `DrawGridPiece` draws a 4x2
  tile payload, uses `GRID_PIECE_NEXT_ROW_DELTA` (`$11`) to move from the
  fourth tile of the first copied row to the same column on the next
  `BG_MAP_ROW_STRIDE` row, and ignores row coordinates at or beyond
  `GRID_DRAW_ROW_LIMIT` (`$20`). Drop redraws clear `GRID_PIECE_TILE_ROWS`
  side-column tiles with `GRID_COLUMN_CLEAR_TILE`, and
  `CommitFallingPieceToBoard` keeps the `$10` guard as
  `COLUMN_TOP_ROW_COMMIT_LIMIT`.
- Bank 0 board-scan round-complete/display locals now expose the slot and display-state
  loops: `InitRoundCompleteTileSlotsLoop`, `SendRoundTransitionFrameLoop`,
  `PlayRoundTransitionDefaultSound`, `ApplyBoardScanRewardScoreAndEggCount`,
  `AbortSend2PDataFrames`, `InitPieceDisplayStateBuild`,
  `ClearPieceDisplayStatesLoop`, and `BuildPieceDisplayStatesLoop`.
- Round-complete display constants now cover the four tile slots, the field
  animation active value, the transition frame/send-frame counts, the transition
  frame toggle mask, and the major reveal frame.
- Bank 0 piece display and menu-selection locals now expose the first/all-state
  forced display paths, game-over display scans, game-turn delay/index tails,
  and the B-type timer-gated `SelectPieceDisplayCode` paths. The field occupancy
  and active display-object scan loops used by that selection path are also
  named.
- Bank 0 `SelectEffectivePieceDisplayCount`, `UpdatePieceDisplayBlink`, and option/BG helper
  locals now expose pending link field-rise consumption, piece-display blink
  slot scanning, option decoration tile writes, box side-row drawing, and
  generic tile-run filling.
- Bank 0 `00:$33F7` is a real link-start confirmation loop, now labeled `WaitLinkStartConfirm`. It had been hidden behind a short `db` escape.
- `Yoshi/yoshi.sym` no longer carries the stale `00:33f7 .data:9` override;
  the symbol file now exposes the recovered `WaitLinkStartConfirm` and
  `ContinueLinkConfirmWait` code labels without a conflicting data block.
- Bank 3 now uses `Bank3GraphicsData` in source for the full `$4000-$7FFF`
  graphics data block. `Yoshi/yoshi.sym` carries the recovered load-site labels
  for the matching, result-record, and link-result copy ranges inside that
  block; at `03:$4000` it keeps `Bank3MatchingTilesTo9000` because the
  disassembler symbol table only preserves one label per address.
- `Yoshi/yoshi.sym` now avoids duplicate label entries for the grid-piece and
  column-sprite pattern table aliases. The source still keeps useful aliases
  like `GridPiecePatternEmptyPayload` and `ColumnSpritePatternFrame2Column0`,
  but the symbol file keeps the table-base labels that regenerated references
  need.
- The two Bank 3 ranges loaded by `SetupResultRecordScreen` are now named
  `Bank3ResultRecordTilesTo9000` and `Bank3ResultRecordTilesTo8800`, matching
  their only confirmed caller and the existing
  `BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE` constant.
- The pause overlay data at `00:$0421-$0440` is now labeled
  `PauseOverlayOamTemplate`. `DrawPauseOverlay` copies eight hardware OAM
  entries (`PAUSE_OVERLAY_OAM_TEMPLATE_SIZE`) directly to `SHADOW_OAM`. The
  entries are now emitted with `OAM_TEMPLATE_ENTRY y, x, tile, attr`, naming
  the shared Y coordinate, eight X coordinates, eight tile IDs, and the DMG
  palette-1 OAM attribute.
- Bank 0 `00:$0068-$00FF` is now labeled `UnusedInterruptVectorPadding`
  instead of the misleading `PositionTable`. It sits between the Joypad
  interrupt vector and `EntryPoint`, has no confirmed references, and is
  represented as 67 little-endian `$3900` padding words, one `$0000` word,
  then 8 final `$3900` words.
- `PauseGame` now exposes the raw `$76` opcode as an explicit `halt`
  instruction. After playing `SND_PAUSE` and clearing `LCD_REDRAW`, execution
  waits for the next interrupt and then falls through to `DrawPauseOverlay`.
- Bank 0 `00:$3839-$3FFF` is graphics data, not code. Result setup copies `$3839` and `$3D39` to VRAM through `VRAMCopySetup`; the remaining tail is now explicit `db`.
- MBC1 bank switching is now named in source:
  - `$2100` = `MBC1_ROM_BANK_REG`
  - `$01` = `ROM_BANK_MAIN_CODE`
  - `$02` = `ROM_BANK_GRAPHICS_0`
  - `$03` = `ROM_BANK_GRAPHICS_1`
- Raw `$2100` writes in real code paths were replaced with `MBC1_ROM_BANK_REG`.
- `docs/source_recovery/graphics_loads.md` records the initial Bank 2/3 and ROM0 graphics-to-VRAM copy map, including overlapping destination/source ranges that still need visual decoding.
- `tools/render_gb_tiles.py` now renders Game Boy 2bpp tile ranges directly from `Yoshi/yoshi.gb` as PNG sheets.
- `docs/source_recovery/tile_sheets/` contains first-pass rendered evidence for the observed Bank 2, Bank 3, and ROM0 graphics ranges.
- Visual evidence from the rendered sheets:
  - Bank 2 contains title logo, option/menu labels, gameplay character/egg tiles, numbers, and playfield UI fragments.
  - Bank 3 is heavily result/high-score oriented; visible text includes `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, `TIME`, `RECORD`, `HI SCORE`, `MARIO`, `LUIGI`, and `NEXT`.
- ROM0 `RoundCompleteSummaryGraphicTileData` renders as A-type
  round-complete summary/reveal graphics. The source now emits the 80 copied
  16-byte tiles as paired `ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS` records,
  keeping each macro below RGBDS's two-digit argument pitfall.
  `RoundCompleteSummaryTextTileData` renders the 17 text tiles used to build
  `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`.
- The following ROM0 tail at `00:$3E49-$3FFF` has no confirmed source
  reference and is dominated by `$39,$00` filler pairs, so the old
  `Bank0TailGraphicsData` label is now `Bank0TailPaddingData`. The source now
  represents its 204 leading `$0039` words with `BANK0_TAIL_PADDING_PREFIX_WORDS`
  and leaves the final 31 bytes as an explicit suffix.
- Bank 3 now has transfer-start labels at the observed load boundaries, and Bank 0 graphics load code refers to those labels instead of raw source addresses.
- After the latest code/data separation, no raw `call $xxxx` / `jp $xxxx` / `jr $xxxx` remains in `bank_000.asm` or `bank_001.asm` from real code paths.
- Temporary compatibility symbols for fake music-data references were removed after the referencing streams were converted from apparent code to explicit `db`.
- `$C6C1` is now `BGM_PREVIEW_TIMER` with medium confidence. `ResetSettings` seeds it with `BGM_PREVIEW_RESET_VALUE`, while `ApplySinglePlayerSettings` reloads it with `BGM_PREVIEW_TIMER_INITIAL` after starting an option preview sound. `$C6C2` is now `BGM_PREVIEW_UNUSED_PERIOD` with low confidence because it receives `BGM_PREVIEW_UNUSED_PERIOD_OPTION0..2` but no direct read has been confirmed yet.
- `UpdateFallAcceleration` contains a level-3 fall-acceleration reload branch shape that
  cannot be reached in the current control flow:
  `PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD` catches lower levels before the later
  `PIECE_FALL_ACCEL_LEVEL3_VALUE` comparison. The branch is now named
  `UnreachableReloadFallAccelTimerForLevel3` to distinguish it from the
  reachable init-time level-3 path.
- Three low-confidence WRAM bytes are now named by the stronger negative
  evidence from the current source: `EGG_COUNT_UNUSED_BYTE` is clear-only with
  the egg counter, `LINK_UNUSED_STAGING_BYTE` is clear-only in
  `ClearLinkRoundState`, and `DROP_ANIM_UNUSED_GRID_ROW_TMP` is written by
  `CalcGridPosition` but not read back from WRAM.
- Bank 0 option UI inline data has been recovered:
  - `00:$1D84-$1DAE` is `$FF`-terminated option label tile text (`A GAME`, `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, `OFF`).
  - `00:$1DAF-$1DBE` is eight option-marker row/column pairs.
  - `00:$1E3D-$1E4F` and `00:$2026-$203A` are row/column/tile triplet lists consumed by `DrawTileTripletList`.
  - `00:$1E75-$1E89` is three 7-byte setting cursor/sprite records copied to `$C290/$C2A0/$C2B0`.
  - `00:$1F4C-$1F4F` and `00:$2C60-$2C63` are option-row upper-bound tables with bytes `$02,$05,$02,$04`.
  - `00:$254E-$254F` is the 2P link settings upper-bound table with bytes `$05,$02`.
  - `00:$2B9D-$2BA0` is a four-byte result-record palette fade sequence written to `rBGP` by `FadeInResultRecordPalette`.
- The labels `UpdatePaletteFade`, `UpdateHighScore`, `LoadSettings`, and `SaveSettings` were renamed to `DrawOptionTextLabels`, `DrawOptionMarkers`, `DrawOptionMarker`, and `DrawTileTripletList` because their behavior is option UI drawing, not palette/high-score/save handling.
- The symbol file is now synced with those option UI names, and the remaining
  misleading option cursor labels are corrected: `SaveConfig1..3` became
  `DrawLevelCursorHighlight`, `DrawSpeedCursorHighlight`, and
  `DrawBgmCursorHighlight`; `DrawOptionItem` became
  `ReturnFromDrawOptionGameTypeLabel`.
- Bank 0 score/result text data has been recovered:
  - `00:$25C3-$25E0` score header strings selected by `LINK_ROLE`.
  - `00:$2622-$2663` two-line result text blocks selected in `Draw2PPreplaySpeedText` and `Draw1PPreplaySpeedText`.
  - `00:$2CBC-$2CD6` result header text, decoding to `1 PLAYER GAME` and `YOSSY EGGS`.
  - `00:$2DE0-$2E2D` restart/result two-line text blocks.
  - `00:$2E38-$2E3B` duplicate `OFF` text.
  - `00:$2E7C-$2EB2` BGM marker strings used by `Draw1PPreplayBgmMarker`.
  - `00:$2734-$2853` preview/result tile table, indexed as six 48-byte three-line entries by `Draw2PPreplayLevelTextAtIndex` and `Draw1PPreplayLevelTextAtIndex`.
  - `00:$2FFB-$304A` countdown digit bitmap table, indexed as ten 8-byte records by `UpdateCountdownTimer`.
- Work estimate checkpoint:
  - The detailed completed-work list, remaining-work list, and estimate rationale
    are recorded in `docs/source_recovery/work_plan_and_estimate.md`.
  - At this checkpoint, `bank_000.asm` / `bank_001.asm` still contain 145 raw
    `$Cxxx` occurrences across 87 distinct `$Cxxx` addresses.
  - The current estimate is 20-40 hours for the remaining high-confidence
    cleanup pass, 100-200 hours for a practical maintainable recovery, and no
    bounded estimate for original-source-equivalent recovery without the lost
    source.
- Round-end local control flow now separates the single-player sound wait,
  1P/2P delay loops, A/B-type tails, and title return. A first attempted label
  placement moved the 1P branch target past the `GAME_TYPE` load; the verifier
  caught the byte difference and the label was moved back before the load.
- `DrawScoreRanking` now exposes the two rank tile normalization branches,
  including the `RESULT_RANK_SPECIAL_POSITION_CODE ->
  RESULT_RANK_FIRST_PLACE` rank tile case for both top and bottom rows. The
  rank display origins, tile-run length, and top/bottom tile bases are now
  named as `RESULT_RANK_*` constants.
- `ProcessRoundResultAndEnterRoundEnd` now exposes the object-slot clear loop, 1P/2P result
  sound branches, and the shared `EnterRoundEndState` tail that seeds
  `ROUND_END_WAIT_TIMER` with `ROUND_END_WAIT_INITIAL_FRAMES` /
  `ROUND_END_WAIT_INITIAL_FRAMES_HI` before entering `GAME_STATE_ROUND_END`.
  Its result sound IDs are named as `SND_RESULT_1P_RANKED`,
  `SND_RESULT_1P_NO_RANK`, `SND_RESULT_2P_NONZERO_RANK`, and
  `SND_RESULT_2P_ZERO_RANK`; its clear loop now names the slots 10-13 clear
  span as `ROUND_COMPLETE_OBJECT_SLOT_CLEAR_BYTES`.
- `HandleRoundEnd` now names the shared `VBLANK_BUSY` delay after result flow as
  `ROUND_END_RESULT_DELAY_FRAMES`; both the 1P and 2P round-end tails use it
  before continuing to the single-player A/B tail or the 2P result panel/title
  decision.
- The round-end title-return cleanup now names the exact sprite object clear
  span as `ROUND_END_SPRITE_OBJECT_CLEAR_BYTES` before `ProcessCurrentResultRecordAndSetupScreen` resets the
  result record staging path.
- `BuildLinkResultScreen` now names the Bank 3 link-result graphics ranges and
  copy sizes: the two `$0800` base tile-block copies and the conditional
  `$0390` / `$0740` terminal overlay copies.
- Rendered Bank 3 link-result tile-sheet evidence now separates the text and
  art-heavy ranges: `$5DD0-$65CF` contains player-name/text/number fragments
  such as `MARIO`, `LUIGI`, `GOOD!`, and `VIEW`-like text, while
  `$65D0-$6DCF` and the conditional `$6AB0/$6E40` overlay ranges contain
  character, egg, and border fragments.
- `UpdateLinkResultMarksAndScreen` now exposes the 2P result counter/mark-screen flow:
  zero/nonzero counter increments, terminal-state detection at three marks,
  result-screen rebuild, filled mark loops, role/result-specific terminal
  outcome blocks, and the link confirmation wait/return path.
  The path now names `LINK_RESULT_TERMINAL_FLAG_CLEAR` for the `$00` value
  stored in `STATE_TRANSITION` before a just-reached `LINK_RESULT_MARK_LIMIT`
  promotes it to `RESULT_FLAG_SET`.
  `SetTerminalLinkResultFlagIfMarkLimitReached`,
  `DrawZeroResultMarksIfAny`, and `DispatchLinkResultScreenMode` now name the
  terminal-flag, zero-mark drawing, and confirm/terminal dispatch tails. The remaining
  anonymous relative branches in Bank 0/1 were the master/nonzero terminal jump
  into `WaitLinkStartConfirm` and the two confirm-wait loopbacks to the next
  `WaitVBlank`; they now target `WaitLinkStartConfirm` and
  `ContinueLinkConfirmWait` directly. The wait-panel half/whole-period frame
  counts are named as
  `LINK_RESULT_WAIT_PANEL_ALT_START_FRAME` and
  `LINK_RESULT_WAIT_PANEL_ANIM_PERIOD`. The terminal-result sound tail is now
  named `PlayTerminalLinkResultSoundAndClearResultAreas`, matching the observed
  sequence that plays the selected result sound, clears serial/send state, and
  clears the status strip and score-value area before dispatching to the
  role/result drawing branches.
- The link result confirm helpers now use role/screen behavior names:
  `DrawLinkResultRoleStatusStrip` fills the status strip according to
  `LINK_ROLE`, and `FillLinkResultWideScoreArea` /
  `FillLinkResultNarrowScoreArea` fill the observed 2x7 and 2x6 score-area
  blocks.
- The final generated Bank 0/1 local labels are now gone from source. The last
  pass named the detached pre-play label tile branch, result-confirm menu and
  serial-confirm waits, link-mode status fill, A-type round-complete summary
  setup, reveal-threshold branches, the manual OAM bonus animation loop, and
  the input-aware wait tail.
- Result-flow immediates now have narrow constants. B-type clear queues
  `ROUND_RESULT_CODE_NONZERO`, falling-piece overflow queues the zero-result
  path, `QueueRoundResult` raises `ROUND_RESULT_PENDING` /
  `RESULT_FLOW_ACTIVE` with `RESULT_FLAG_SET`, return-to-title clears the flow
  with `RESULT_FLOW_INACTIVE`, bit-7 link result packets use
  `LINK_RESULT_PACKET_FLAG` / `LINK_RESULT_PACKET_BIT`, bit 0 carries the
  asynchronous result code, `LINK_RESULT_MARK_LIMIT` is the three-mark terminal
  threshold, `RESULT_RANK_NONE` documents the 1P no-rank / game-over entry, and
  equal 2P master-side results return `RESULT_RANK_FIRST_PLACE`. The same link
  packet pass now names
  `LINK_FIELD_COUNT_PACKET_BIT` and `LINK_FIELD_EVENT_BIT` beside the existing
  `$20/$40` packet flag constants.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Use `rg`, `nl`, `sed`, and small scripts for static analysis | Fast local inspection, keeps evidence traceable. |
| Create persistent planning files in the repository root | Source recovery will span many steps and needs durable memory in the project. |
| Start with memory-map recovery | WRAM/HRAM naming will improve routine naming and comments across banks. |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| Planning files were accidentally placed in `/Users/akihito/git` | Re-created them under `/Users/akihito/git/mgbdis` and deleted the misplaced copies. |
| Initial VRAM copy rename changed two HRAM operand bytes | Compared rebuilt ROM to `Yoshi/yoshi.gb`, found real differences at offsets `$4B45/$4B48`, and corrected `VRAMCopyDMA` labels so the build is byte-identical again. |
| First attempt at `FieldRowDeltaTable` had one extra byte and then a byte-order mismatch | Used `make -B`, `cmp -l`, and `xxd` against `Yoshi/yoshi.gb` to restore exact `00:$230F-$234B` bytes and `UpdateFieldTimers` at `00:$234C`. |
| Two Bank 3 graphics labels were first placed at repeated-looking rows, changing `ld hl` immediates for `$5C00` and `$6AB0` | Used an address-counting `awk` check over 16-byte `db` rows, moved the labels to exact `$5C00` and `$6AB0`, then rebuilt byte-identical. |

## Resources
- `Yoshi/yoshi.gb`
- `Yoshi/game.gb`
- `Yoshi/bank_000.asm`
- `Yoshi/bank_001.asm`
- `Yoshi/bank_002.asm`
- `Yoshi/bank_003.asm`
- `Yoshi/yoshi.sym`
- `Yoshi/ARCHITECTURE.md`
- `Yoshi/SERIAL_PROTOCOL.md`

## Evidence Limits And Optional Questions
- Which existing labels came from user/manual analysis versus automatic symbol recovery?
- Which game states correspond to demo/attract behavior, if present?
- Which data blocks are currently mis-disassembled as instructions?
- The final raw gameplay/score-adjacent WRAM references are now explicit
  unresolved constants rather than bare addresses. `SCORE_PRESERVED_UNUSED_BYTE`
  (`$C620`) is set to `1` in `ResetTitleState` and preserved while
  `ResetScoreAccumulatorAndDigits` clears `SCORE_BCD_LOW` through `SCORE_DIGITS`;
  `SCORE_UNUSED_TILE_BASE_SOURCE` (`$C672`) is seeded with
  `SCORE_UNUSED_TILE_BASE_INITIAL` (`$30`) in `InitBTypeFallTimingAndBoardSeed`,
  and `AddScore` copies it to `$C629` and its swapped form to `$C628`. No
  independent consumer has been confirmed.
- The landing/scan bytes `$C69D/$C6AE/$C6BF/$C6C0` are now named with
  `UNRESOLVED_` prefixes. The reset-byte and reset-timer names deliberately
  encode only observed write/reset behavior; the scan counter is real
  read/write state but still lacks a proven semantic unit.
- The misleading Bank 0 helper names `DrawString`, `DrawNumber`, and
  `DrawCharacter` are now corrected to `WaitVBlankFrames`,
  `ShiftMatchingOamPairX`, and `FillBytesWithD`. `DrawNumber`'s old address was
  also being used as the immediate value `$1203`; that call site now uses
  `WIN_SCREEN_RIGHT_PANEL_RECT_SIZE` so the helper name no longer carries a
  hidden rectangle-size constant.
- The adjacent `DrawDigit` and `WaitFrames` labels are now corrected to
  `ReloadGameTilesAndRequestRedraw` and `WaitFramesSetTransitionOnInput`.
  The first reloads game tiles after matching/link result transitions and sets
  `LCD_REDRAW`; the second waits a fixed number of frames while recording any
  joypad press as `ROUND_COMPLETE_NO_INPUT_TRANSITION_SENTINEL` in
  `STATE_TRANSITION`.
- Final checklist audit closes the recovery pass at 541 / 541 items complete.
  The remaining low-confidence areas stay documented as evidence limits rather
  than broadened into speculative names. The final verification gate remains
  byte-identical: `tools/verify_yoshi_build.sh` passes,
  `Yoshi/yoshi.gb` and `Yoshi/game.gb` share SHA-256
  `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`, and
  the raw Bank 0/1 WRAM/direct-branch/generated-label/anonymous-branch scans
  return no matches.
