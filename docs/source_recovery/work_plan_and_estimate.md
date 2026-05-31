# YOSSY NO TAMAGO Source Recovery Work Plan And Estimate

This document records what has been done, what evidence remains intentionally
low-confidence, and why source recovery took substantial time. The goal is
source recovery, not a cosmetic rename pass: each accepted change must remain
byte-identical to `Yoshi/yoshi.gb`.

## Current Status

- Branch: `codex/yoshi-recovery-review-stack`
- Source recovery commit at this checkpoint:
  `6c35953 Complete recovered Yossy no Tamago source`
- Worktree caveat: local untracked notes files are intentionally ignored
  unless they are directly part of the recovery task.
- Current invariant: `Yoshi/game.gb` rebuilds byte-identical to
  `Yoshi/yoshi.gb`.
- Current ROM SHA-256 for both files:
  `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
- Current raw direct branch scan:
  `rg -n 'call \$|jp \$|jr \$' Yoshi/bank_000.asm Yoshi/bank_001.asm`
  returns no matches.
- Current raw WRAM-style references in `bank_000.asm` / `bank_001.asm`:
  0 occurrences, 0 distinct `$Cxxx` addresses. Remaining unresolved WRAM roles
  are represented by explicit `UNRESOLVED_*` constants or low-confidence
  `SCORE_*UNUSED*` constants.
- Current generated local label definitions in `bank_000.asm` / `bank_001.asm`:
  0 occurrences. The remaining source labels in these banks now have semantic
  names rather than `jr_000_*` placeholders.
- Current anonymous relative `@+` / `@-` branches in `bank_000.asm` /
  `bank_001.asm`: 0 occurrences.
- Current checklist progress: 541 / 541 items complete, 100%. The remaining
  low-confidence items are documented evidence limits, not open checklist work.

## Completed Work

### Baseline And Build

- Established `Yoshi/yoshi.gb` as the behavioral baseline.
- Confirmed the ROM is 64KB, MBC1, with four 16KB banks.
- Confirmed RGBDS rebuild produces byte-identical `Yoshi/game.gb`.
- Named the cartridge header metadata byte constants, emitted the fixed
  Nintendo logo through RGBDS's `NINTENDO_LOGO` macro, and preserved the literal
  title bytes.
- Added `tools/verify_yoshi_build.sh` to run the current rebuild, checksum,
  header, generated-artifact, and raw-branch verification gate.
- Added persistent planning files:
  - `task_plan.md`
  - `findings.md`
  - `progress.md`
- Added baseline and memory-map notes under `docs/source_recovery/`.

### Bank, State, And Runtime Structure

- Named the MBC1 bank register and bank IDs:
  `MBC1_ROM_BANK_REG`, `ROM_BANK_MAIN_CODE`,
  `ROM_BANK_GRAPHICS_0`, `ROM_BANK_GRAPHICS_1`.
- Documented Bank 1 as the normal active code bank and Banks 2/3 as graphics
  banks loaded temporarily.
- Named the seven observed `GAME_STATE` values and documented the main state
  machine.
- Recovered the pre-play/title menu flow and link-start wait path.

### Data/Code Separation

- Converted many fake-code ranges into explicit data blocks while preserving
  exact bytes:
  - Bank 0 option UI strings and marker tables.
  - Bank 0 preview/result/countdown text and digit tables.
  - Bank 0 game-turn parameter table.
  - Bank 0 matching/result OAM templates and scoring tables.
  - Bank 0 round-complete tables and field animation delta tables.
  - Bank 0 tail graphics.
  - Bank 1 sprite frame/tile/layout tables.
  - Bank 1 sound setup support tables.
  - Bank 1 music sequence streams and tail sound/wave tables.
- Verified after each conversion with byte-identical rebuilds.

### Memory Map And WRAM/HRAM Recovery

- Named and documented key HRAM:
  - OAM DMA routine address.
  - VRAM copy queue fields.
  - unused secondary VRAM-copy slot.
  - joypad, VBlank, serial, and game-state bytes where evidence supports it.
- Named and documented many WRAM structures:
  - sound engine work RAM `$C000-$C0ED`
  - score BCD/display digits
  - logical sprite object page `$C200-$C2FF`
  - shadow OAM `$C400-$C49F`
  - BG map shadow `$C4A0-$C607`
  - options and active game settings
  - piece display/shuffle state
  - falling-piece timing state
  - column top-row and drop cursor animation state
  - field animation slot cursors/flags/timers
  - elapsed timers
  - egg counter and egg text animation state
  - link settings, link send queue, result handshake state
  - countdown digit buffers
  - result records and reset-persistent magic

### Graphics And Sound

- Added a dependency-free GB 2bpp tile renderer:
  `tools/render_gb_tiles.py`.
- Generated first-pass rendered tile-sheet evidence under
  `docs/source_recovery/tile_sheets/`.
- Documented graphics load ranges and VRAM destinations.
- Recovered first-pass sound/music command semantics and many `PlaySound`
  call-site names.

### Recent Completed Chunks

- `76f3000 Name falling piece timing state`
- `12aabd2 Name piece display state array`
- `6c9fab5 Name piece display shuffle state`
- `6735114 Name piece display count and column seed`
- `71edf6c Name fall acceleration timer`
- `a848747 Name result flow flag`
- `14a83f6 Name queued round result state`
- `74dda5b Name peer result code`
- `e111ecb Name link send drop lock`
- `400d34b Name elapsed timer state`
- `d81195a Name result outcome flags`
- `549caf5 Name field column tile pattern index`
- `674607a Name egg text animation state`
- `14ad063 Name round complete parameter index`
- `f2efc13 Name round complete tile origin`
- `83e3437 Name link result mark counts`
- `5f8866e Name piece display remaining counter`
- `2ff999c Name progression level`
- `f84ddff Name tilemap shadow buffer`
- `db28094 Name result record state`
- `f261b34 Name piece display object base Y`
- Current uncommitted recovery chunks include field-column effect object type,
  board bottom visible cell, startup WRAM/manual OAM constants, and BG map
  shadow slice-copy state.
- Current uncommitted recovery also includes 2P result mark tilemap origins.
- Current uncommitted recovery also includes wave RAM and countdown digit VRAM
  destination constants.
- Current uncommitted recovery also includes graphics VRAM destination constants
  and matching/result shadow OAM entry-field constants.
- Current uncommitted recovery also includes Bank 2 graphics copy size
  constants for title, pre-play, gameplay, and 2P tile loads.
- Current uncommitted recovery also renames Bank 2 pre-play and 2P graphics
  ranges by load role: `PreplayMenuOverlayTiles`,
  `TwoPlayerSharedTiles`, and `TwoPlayerNonMasterTiles`, with matching
  destination/copy-size constants and rendered evidence names.
- Current uncommitted recovery also labels the unloaded Bank 2 tail range as
  `Bank2UnusedTailTileData` and adds a rendered evidence sheet for the
  noise/padding-like `$73D0-$7FFF` data.
- Current uncommitted recovery also removes the stale `yoshi.sym`
  `00:33f7 .data:9` override so the symbol file matches the recovered
  `WaitLinkStartConfirm` / `ContinueLinkConfirmWait` code boundary.
- Current uncommitted recovery also includes Bank 3 matching/result-record
  graphics copy size constants for the fixed `$0800` tile-block loads.
- Current uncommitted recovery also renames the full Bank 3 graphics block to
  `Bank3GraphicsData`, syncs the Bank 3 load-site labels into `Yoshi/yoshi.sym`,
  and renames the full rendered evidence sheet.
- Current uncommitted recovery also deduplicates source-only grid-piece and
  column-sprite pattern aliases from `Yoshi/yoshi.sym`, keeping the table-base
  labels needed by regenerated references while preserving the richer aliases
  in source.
- Current uncommitted recovery also narrows the Bank 3 result graphics labels
  to `Bank3ResultRecordTilesTo9000/8800` and renames the rendered Bank 3
  matching/result-record evidence sheets by destination rather than source
  address.
- Current uncommitted recovery also names the pause overlay OAM template and
  replaces its raw 32-byte copy size with `PAUSE_OVERLAY_OAM_TEMPLATE_SIZE`.
- Current uncommitted recovery also renames the unreferenced `00:$0068-$00FF`
  vector-padding label from `PositionTable` to
  `UnusedInterruptVectorPadding`, and structures its bytes as repeated
  little-endian padding words with one zero word.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  reset vectors, interrupt vectors, and cartridge header labels; the symbol
  file now marks `00:$0000-$0067` as code and `00:$0104-$014F` as header data.
- Current uncommitted recovery also restores the pause wait opcode from
  `db $76` to the explicit `halt` instruction before `DrawPauseOverlay`.
- Current uncommitted recovery also restores the ROM copy of the HRAM OAM DMA
  routine from raw bytes to explicit instructions and marks the `00:$01C8`
  range as code.
- Current uncommitted recovery also renames `$FF8D` from the misleading
  `TEXT_FADE` role to `UI_SCRATCH`, matching its observed reuse by
  piece-display, pre-play text, result-record, result-rank, and link confirm
  drawing paths.
- Current uncommitted recovery also renames the round-result entry from
  `ProcessNewHighScore` to `ProcessRoundResultAndEnterRoundEnd`, matching the
  B-type clear, game-over, queued 2P result, and link-result call sites that all
  enter round-end flow through this routine.
- Current uncommitted recovery also removes stale high-score wording from the
  `RESULT_FLOW_ACTIVE` / `ROUND_RESULT_PENDING` comments and round-result state
  notes, while leaving actual result-record/high-score graphics notes intact.
- Current uncommitted recovery also renames the Bank 1
  `SpriteFrameTable_GameOverPiece` / `SpriteTileList_GameOverPiece*` /
  `SpriteLayout_GameOverPieceTwoTileRow` labels to `PieceDisplay` names because
  `SpriteUpdatePointerTable` maps `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` to that
  frame table.
- Current uncommitted recovery also includes round-complete tilemap origins and
  tile constants.
- Current uncommitted recovery also includes result record row labels,
  placeholders, and the renamed placeholder helper.
- Current uncommitted recovery also names the Bank 1 sound wave-pattern pointer
  table and dedicated/shared wave-pattern data labels.
- Current uncommitted recovery also names the `SoundIndexEntry_00` sentinel
  flags/pointer fields while keeping its playable-sound role unconfirmed.
- Current uncommitted recovery also includes result record digit-rendering
  constants: score/level/detail digit counts, leading-zero policy values,
  low-nibble digit masking, tile base, B-type timer separator, and the
  post-render row delta.
- Current uncommitted recovery also includes result record staging/comparison
  constants: empty record head marker, first rank index, score/level/detail
  compare counts, level offset, and record-size stepping during rank scan.
- Current uncommitted recovery also applies the first-rank index constant to the
  A/B result-record down-shift decision during insertion.
- Current uncommitted recovery also includes result record palette-fade timing:
  the four-entry palette sequence, `RESULT_RECORD_PALETTE_FADE_STEP` records,
  and the per-step VBlank wait.
- Current uncommitted recovery also includes result record setup fill-tile and
  palette-value constants for the BG shadow clear, header/type label, B-type
  type-label patch, and the four palette fade bytes.
- Current uncommitted recovery also includes 2P result header, badge, outcome,
  and status tilemap origins.
- Current uncommitted recovery also includes 2P result screen tile constants:
  role-swapped header/badge bases, terminal outcome/status bases, wait-panel
  tile pairs, score clear/fill areas, and confirm-panel tile/rect constants.
- Current uncommitted recovery also includes Bank 3 link-result graphics range
  labels, rendered evidence names, and copy size constants for the 2P result
  screen rebuild path.
- Current uncommitted recovery also refines the rendered Bank 3 link-result
  tile-sheet evidence: the `$5DD0` range carries link-result name/text/number
  fragments, while `$65D0` and the conditional overlay ranges are character,
  egg, and border fragments.
- Current uncommitted recovery also includes 2P result wait-panel animation
  timing constants and the final Bank 0/1 anonymous relative confirm-loop
  branches retargeted to named link-confirm wait labels.
- Current uncommitted recovery also includes 2P result/high-score sound ID
  constants for the terminal nonzero/zero result sounds and the confirm/menu
  wait sounds.
- Current uncommitted recovery also names the terminal link-result
  sound-and-clear tail as `PlayTerminalLinkResultSoundAndClearResultAreas`,
  matching the selected sound playback, serial/send clear, and status/score
  area clears before role/result drawing.
- Current uncommitted recovery also includes title screen frame/panel tilemap
  origins from `InitTitleUI`.
- Current uncommitted recovery also names the board-cell lanes: the odd byte is
  `BOARD_CELL_VISIBLE_PAYLOAD_OFFSET`, and the paired even byte is
  `BOARD_CELL_UNREAD_PAIR_OFFSET` because the live draw, initial-fill,
  drop-swap, landing, and scan paths all use odd visible payload offsets or the
  `$0F` end sentinel.
- Current uncommitted recovery also names the slot 1-8 clear span used by
  `ClearPieceSpriteObjectSlots` as `PIECE_SPRITE_OBJECT_CLEAR_BYTES`.
- Current uncommitted recovery also includes the 2P field occupancy scan/count
  packet path.
- Current uncommitted recovery also names the 2P field occupancy two-digit
  conversion base as `FIELD_OCCUPANCY_COUNT_DECIMAL_BASE`.
- Current uncommitted recovery also includes result record screen setup layout
  origins and the renamed `FillResultRecordBoxRow` helper.
- Current uncommitted recovery also includes A-type round-complete summary
  layout origins and the `00:$3799-$37DF` message/reveal data island.
- Current uncommitted recovery also includes matching/link result animation
  layout origins at `$C4ED/$C4CA/$C59B/$C543/$C571`.
- Current uncommitted recovery also renames the stale high-score-table label to
  `UpdateLinkResultMarksAndScreen`, matching the 2P result mark counters and
  screen rebuild behavior.
- Current uncommitted recovery also renames the link result confirm helpers:
  `DrawLinkResultRoleStatusStrip`, `FillLinkResultWideScoreArea`, and
  `FillLinkResultNarrowScoreArea`.
- Current uncommitted recovery also renames the link result menu, confirm-panel,
  serial-confirm, and game-tile reload helpers:
  `WaitTerminalLinkResultMenuConfirm`,
  `DrawLinkResultConfirmPanelsAndWait`, and
  `WaitLinkResultConfirmAndReloadTiles`.
- Current uncommitted recovery also includes `ProcessMatching` animation local
  cleanup: matching-state clamp/store, intro and result panel blink loops, OAM
  tile-ID setup, OAM slide loops, result-panel right-edge fill, final OAM tile
  setup, and final upward OAM movement.
- Current uncommitted recovery also names `ProcessMatching` setup constants:
  state clamp count, BG map VRAM clear size/tile, matching LCDC flags, and the
  four-entry middle / two-entry pair OAM template sizes.
- Current uncommitted recovery also names `ProcessMatching` animation timing,
  panel-fill, and OAM-movement constants for the intro scroll/blink,
  result-panel scroll/blink and staged fills, horizontal OAM slides, final OAM
  tile base, upward movement, and score-application wait.
- Current uncommitted recovery also includes matching animation sound ID
  constants for the intro blink, result-panel blink, and OAM slide sound call
  sites.
- Current uncommitted recovery also includes `ProcessRoundResultAndEnterRoundEnd` result/rank
  sound ID constants for the single-player ranked/no-rank branches and the
  two-player nonzero/zero result branches, plus the slots 10-13 object clear
  span and round-end wait timer low/high initial bytes before round-end result
  flow.
- Current uncommitted recovery also audits direct `PlaySound` IDs after the
  link-result helper rename. The sound notes now use
  `DrawLinkResultConfirmPanelsAndWait` and
  `WaitTerminalLinkResultMenuConfirm`, and the remaining numeric sound-index
  labels are documented as lacking direct game-code call-site evidence.
- Current uncommitted recovery also names the shared round-end result delay
  frame count used by both the 1P and 2P tails after result flow settles.
- Current uncommitted recovery also names the exact sprite-object clear span
  used by `ClearRoundEndSpriteObjectsAndRecord` before `ProcessCurrentResultRecordAndSetupScreen`.
- Current uncommitted recovery also includes the link field-rise pending-consume
  none value, the sound ID used by `PlayPendingFieldRiseSound`, and the
  screen-state limit used while consuming pending field-rise packets.
- Current uncommitted recovery also names the 2P pre-play settings packet
  nibble mask used when unpacking received level/speed values.
- Current uncommitted recovery also renames the 2P settings option-count table,
  names the level/speed option counts used as exclusive upper bounds, and
  structures its entries with `LINK_SETTINGS_OPTION_COUNT_ENTRY`.
- Current uncommitted recovery also names the shared settings/result blink phase
  toggle mask used by `TickSettingsBlink`.
- Current uncommitted recovery also includes matching score/result display
  cleanup: `ApplyMatchingScoreBonusAndWait`, `WaitMatchingScoreSoundEndLoop`,
  and `DrawResultScoreDigitsLoop`.
- Current uncommitted recovery also renames `UpdateLevel` to
  `DrawMatchingResultStats`, matching its score/level/speed/time result-screen
  drawing role, and names the associated display constants: score/level/time
  label tile bases, result digit mask/base, score digit count, speed tile base,
  time separator tile, label rectangle sizes, and the matching-score LCDC flags.
- Current uncommitted recovery also renames the misleading `FillRectAlt` helper
  to `WaitAnyButtonPress` and names its low-nibble button mask as
  `PADF_ANY_BUTTON`; the result-record blinking input poll now uses the same
  button-only mask.
- Current uncommitted recovery also includes Bank 0 FillRect/gameplay update
  display local cleanup: `FillRectRowLoop`, `FillRectColumnLoop`,
  `UpdateGameplayObjectsAndCheckBTypeClear`, `UpdateGameplayObjectSlotsLoop`,
  `CheckBTypeColumnClearLoop`, `TickFallTimerForActiveGameplayObjects`,
  `UpdatePieceFallTimer`, `ReloadPieceFallTimer`,
  `UpdatePieceDisplayByGameType`, `RunBTypePieceDisplayUpdate`,
  `CheckGameplayObjectSlotsActive`, `ScanGameplayObjectSlotsLoop`, and the
  `UpdateFallAcceleration` fall-acceleration reload branches.
- Current uncommitted recovery also includes explicit unresolved constants for
  the remaining score-adjacent and landing/scan WRAM bytes, replacing the final
  raw `$Cxxx` operands in Bank 0/1 code.
- Current uncommitted recovery also includes Bank 0 helper label cleanup:
  `WaitVBlankFrames`, `ShiftMatchingOamPairX`, `FillBytesWithD`,
  `ClearManualOamPair`, `ReloadGameTilesAndRequestRedraw`,
  `WaitFramesSetTransitionOnInput`, and `WIN_SCREEN_RIGHT_PANEL_RECT_SIZE`.
- Current uncommitted recovery also names the BGM preview reset value, preview
  timer reload, write-only per-option period values, and explicit BGM option
  values used by `ApplySinglePlayerSettings`.
- Current uncommitted recovery also macro-structures the link-role sound
  channel heads and short `$FD/$FE` call/loop records, preserving the split
  `LinkSlaveChannel3Sequence` operand boundary at `MusicSequenceData_71e4`.
- Current uncommitted recovery also macro-structures the confirm sound channel
  heads, including pitch-slide, channel-3 nested-sound-note, rest, and sequence
  end records.
- Current uncommitted recovery also macro-structures the link-result nonzero
  and zero channel heads, keeping pitch/duration bytes raw.
- Current uncommitted recovery also macro-structures the link-result
  confirm/menu wait setup records and short `$FD/$FE` branch records while
  keeping pitch/duration bytes raw.
- Current uncommitted recovery also macro-structures the link-result
  confirm/menu wait phrase labels with generic octave, rest-note, channel-3
  nested-sound-note, loop, and sequence-end command records.
- Current uncommitted recovery also macro-structures the remaining inline
  link-result confirm/menu wait phrase command bytes with generic octave and
  rest-note records.
- Current uncommitted recovery also includes round-complete reveal helper
  cleanup: `RevealRoundComplete2x2Block`, `RevealRoundComplete3x2Block`,
  `RevealRoundComplete3x4Block`, and `AddScoreAndAnimateManualOamPair`. The
  A-type bonus path now names the 500/200/100/50 score deltas, manual-OAM tile
  arguments, and bonus animation timing.
- Current uncommitted recovery also includes elapsed-timer helper cleanup:
  `DrawRoundTimerDigits`, `ClearRoundTimerDigitsAndResume`, and
  `ClearTotalTimerDigitsAndResume`.
- Current uncommitted recovery also includes round-local link-state helper
  cleanup: `ClearLinkRoundState`.
- Current uncommitted recovery also includes slot-0 player cursor helper
  cleanup: `InitPlayerCursorObject`.
- Current uncommitted recovery also includes coordinate-based tilemap helper
  cleanup: `FillTilemapRectByCoord` and `DrawSequentialTileRowByCoord`.
- Current uncommitted recovery also includes sprite object buffer clear helper
  cleanup: `ClearSpriteObjectBuffer`.
- Current uncommitted recovery also includes playfield HUD helper cleanup:
  `DrawPlayfieldLevelDigits`, `DrawPlayfieldSpeedValue`,
  `DrawPlayfieldEggDisplay`, and `DrawEggTextFrame0`.
- Current uncommitted recovery also includes playfield timer/link header helper
  cleanup: `DrawBTypeTimerHeaderAndDigits`,
  `DrawPlayfieldRoundTimerDigits`, and
  `DrawTwoPlayerPlayfieldRoleHeaders`.
- Current uncommitted recovery also includes playfield side-panel layout helper
  cleanup: `Draw1PPlayfieldSidePanelLabelRow0`,
  `DrawPlayfieldSidePanelLabelRow1`,
  `DrawPlayfieldBottomColumnMarkers`, and the three
  `Blank*PlayfieldSidePanelRows` helpers.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  egg text animation entry labels.
- Current uncommitted recovery also includes gameplay input/fall-delay helper
  cleanup: `HandlePlayfieldInput`, `GetLevelFallDelay`, and
  `DecrementPieceDisplayRemaining`.
- Current uncommitted recovery also includes `HandlePlayfieldInput` local
  cleanup: cursor/drop-start input branches and Down-held fast-fall clamp
  loops.
- Current uncommitted recovery also includes playfield board/piece setup helper
  cleanup: `InitPlayfieldBoardAndPieceState`,
  `ClearPieceSpriteObjectSlots`, `ClearRoundLandingAndResultState`,
  `InitBTypeFallTimingAndBoardSeed`, `FillInitialBoardWithVBlankWait`, and
  `FillInitialBoardColumns`.
- Current uncommitted recovery also includes selected-column piece staging
  helper cleanup: `GetSelectedColumnTopRow`,
  `StagePiecePayloadInSelectedColumn`, and
  `ClearCurrentGameplaySpriteObjectRecord`.
- Current uncommitted recovery also includes `UpdateFallingPieceMotionAndLanding` fall/landing
  local cleanup: fall-position advance, reached-column handling,
  landed-piece redraw/top-row update, overflow result branch, selected object
  clear loop, selected-column carry tails, and B-type fall-timing init
  branches.
- Current uncommitted recovery also labels the static-dead one-byte
  `UnreachedClearLandedGameplayObjectPop` fragment after the landed-object
  cleanup trampoline; current control flow either jumps over it or returns
  before it.
- Current uncommitted recovery also includes board/piece setup local loop
  cleanup: board clear, column-top seed, piece-display code pool init,
  initial-board fill/wait loops, rotate-piece return paths, A/B-type setup
  tails, and capped level-fall-delay table read.
- Current uncommitted recovery also includes board scan target helper cleanup:
  `FindBoardScanTargetRow` and `ReadBoardCellAtColumnRow`.
- Current uncommitted recovery also includes board-scan animation/cell-read
  local cleanup: scan distance parameter storage, animation step loop, trigger
  draw, send-frame wait, target-row return paths, and board-cell address carry
  tails.
- Current uncommitted recovery also names the board-scan transition frame-limit
  table values as `BOARD_SCAN_TRANSITION_FRAME_LIMIT_1..4`.
- Current uncommitted recovery also macro-structures the matching tile-base
  index and board-scan transition frame-limit lookup tables as one-byte record
  entries.
- Current uncommitted recovery also includes round-complete send/display local
  cleanup: round-complete tile slot init, transition frame send loop, reward
  sound/reward tail, `Send2PData` early abort, and `BuildPieceDisplayStatesForCount`
  state-clear/build loops. The same path now names the round-complete reveal
  sound IDs, tile-slot count, field-animation active value, and transition
  frame/send constants.
- Current uncommitted recovery also includes piece display/menu-selection local
  cleanup: first/all forced-state application loops, game-over display scans,
  game-turn delay/index tails, B-type timed special-selection paths, return
  code labels, field occupancy scan loops, and active display-object counts.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` to the recovered
  full `GameTurnParamTable` boundary at `00:$0B8D-$0ED4`, keeping
  `GameTurnParamTableContinuation` only as an internal exact-address landmark.
- Current uncommitted recovery also names the `GameTurnParamTable` record
  structure: four-byte records, `GAME_TURN_PARAM_RECORD_SHIFT`, step timer,
  display count, fall delay offsets, 210 records, and the always-`$01` tail byte
  that still has no confirmed reader.
- Current uncommitted recovery also macro-structures the full
  `GameTurnParamTable` body with `GAME_TURN_PARAM` records, preserving the
  `GameTurnParamTableContinuation` exact-address landmark by splitting the one
  record that crosses `00:$0C40` with `GAME_TURN_PARAM_SPLIT_HEAD` and
  `GAME_TURN_PARAM_SPLIT_TAIL`.
- Current uncommitted recovery also labels the two unreachable game-turn delay
  clamp fragments before the live delay-store labels at `00:$19FD` and
  `00:$1A74`.
- Current uncommitted recovery also macro-structures the field animation delta
  tables as `FIELD_ANIM_DELTA_PAIR` X/Y records followed by
  `FIELD_ANIM_END_SENTINEL`.
- Current uncommitted recovery also includes link field-rise selection, blink,
  and option/BG helper local cleanup: pending field-rise consumption,
  piece-display blink slot scan/toggle returns, option decoration tiles, box
  side-row drawing, and tile-run fill loops.
- Current uncommitted recovery also includes option marker, detached pre-play,
  BGM settings, option value, and cursor-highlight local cleanup. The symbol
  file now uses the recovered option UI names instead of the old
  `UpdateHighScore`/`SaveConfig*` style labels.
- Current uncommitted recovery also includes serial interrupt, string-copy,
  2P pre-play init, and field-animation end local cleanup:
  `FinishSerialInterrupt`, `CopyStringToGridLoop`,
  `InitTwoPlayerPreplayScreen`, and `EndFieldAnimSlot10..13`.
- Current uncommitted recovery also includes the 2P pre-play settings exchange
  wait labels and result-record one-time initialization labels:
  `Start2PPreplaySettingsExchange`, `Wait2PPreplaySettingsSerialDone`,
  `InitATypeResultRecord0..2`, and `InitBTypeResultRecords`.
- Current uncommitted recovery also includes countdown digit buffer build/blit
  local cleanup: the phase 0/1 buffer merge loops and the doubled-byte VRAM
  staging loops in `UpdateCountdownTimer` and `RandomNext`.
- Current uncommitted recovery also names the countdown buffer phase toggle,
  high/low nibble masks, and the phase-1 spill pixel mask used while merging
  shifted digit bitmap columns.
- Current uncommitted recovery also includes round-end, rank, high-score, and
  2P result-panel local cleanup: round-end sound/delay loops, score-rank tile
  normalization, result-object clearing, two-player result mark fill loops,
  terminal result branches, and the link-confirm wait/return paths.
- Current uncommitted recovery also includes piece-display shuffle and initial
  B-type board-fill constants: the shared `$38` shuffle mask, explicit
  piece-display codes `$01/$02/$03/$04/$08`, pool offset `+3`, and the
  adjacent-match wrap sentinel/value used by `AvoidInitialBoardAdjacentDuplicate`.
- Current uncommitted recovery also names the B-type column top-row seed table
  values by level and renames the A-type game-turn level-start table to
  `GameTurnLevelStartIndexTable` with ten-record start-index constants.
- Current uncommitted recovery also macro-structures the Bank 0 level-index
  lookup tables with `B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY`,
  `GAME_TURN_LEVEL_START_INDEX_ENTRY`, and `LEVEL_FALL_DELAY_ENTRY`.
- Current uncommitted recovery also decodes the A-type round-complete summary
  strings as `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`, and renames the
  two ROM0 queued tile blocks to `RoundCompleteSummaryGraphicTileData` and
  `RoundCompleteSummaryTextTileData`. The graphic tile block now uses paired
  `ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS` records for the 80 copied tiles.
  The text tile block now uses `ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE` records
  keyed by the same tile ID constants used by the message strings, and
  Cxxx-shaped glyph rows are written as binary bitmap literals to keep the
  raw-WRAM scan address-specific.
- Current uncommitted recovery also renames the unreferenced ROM0 tail at
  `00:$3E49-$3FFF` to `Bank0TailPaddingData`; the range has no confirmed load
  target and now uses `BANK0_TAIL_PADDING_PREFIX_WORDS` repeated `$0039` words
  for the 204-word prefix before the 31-byte suffix.
- Current uncommitted recovery also includes piece-display blink constants:
  the eight display-object slots scanned from slot 1, the active display-object
  type check, the `$10` frame-toggle mask, and the `$08` blink-exempt state
  beside the existing forced state `$07`.
- Current uncommitted recovery also names `SelectPieceDisplayCode`'s B-type
  timer/occupancy gates and the random branch thresholds used after `Multiply`
  in the default, first-forced, and timed-special paths.
- Current uncommitted recovery also includes board/tile pattern helper cleanup:
  consumer-specific names for the grid-piece and column-sprite pattern offset
  helpers, copy helpers, and pattern tables, plus the 8-byte and 12-byte record
  stride constants. The same chunk now splits grid-piece payload records `0..8`,
  column-sprite frame-2/frame-1 blocks, and the 16-byte unreached
  column-sprite tail.
- Current uncommitted recovery also names the direct grid-piece pattern tile
  bytes with `GRID_PIECE_PATTERN_*_TILE` constants, matching the two four-tile
  rows copied by `DrawGridPiece` for each 8-byte payload record.
- Current uncommitted recovery also names the live column-sprite pattern bytes
  with `COLUMN_SPRITE_PATTERN_*_ENCODED_TILE` constants, preserving the
  source-byte encoding used by `CopyEncodedTilePatternRow4SkipFF`.
- Current uncommitted recovery also names the four-row
  `UnreachedColumnSpritePatternTailRows` bytes with scoped
  `UNREACHED_COLUMN_SPRITE_TAIL_*_TILE` constants while keeping them separate
  from the confirmed live encoded column-sprite path.
- Current uncommitted recovery also macro-structures the grid-piece and
  column-sprite four-tile pattern rows with `GRID_PIECE_PATTERN_ROW` and
  `COLUMN_SPRITE_PATTERN_ROW`.
- Current uncommitted recovery also names the `UnusedFillBoardDataPattern`
  fragment's local pattern bounds and the currently ignored
  `DROP_ANIM_ACCEPTED_RETURN_VALUE`.
- Current uncommitted recovery also names the matching tile-base index scaling
  used to turn `MatchingTileBaseIndexTable` entries into middle/final OAM tile
  IDs.
- Current uncommitted recovery also names the Bank 1 player cursor and
  round-complete sprite frame tile/layout records by their consuming frame
  tables, replacing another set of address-only `SpriteTileList_42xx` /
  `SpriteLayout_42xx` labels.
- Current uncommitted recovery also names the Bank 1 settings cursor and
  round-transition sprite frame tile/layout records, including the shared
  two-tile row layout and the round-transition two/four/six/eight-sprite
  layouts.
- Current uncommitted recovery also names the Bank 1 piece-display sprite frame
  tile/layout records, eliminating the remaining address-only
  `SpriteTileList_42xx` / `SpriteLayout_42xx` labels in the recovered sprite
  table block.
- Current uncommitted recovery also macro-structures the Bank 1 sprite frame
  tables with `SPRITE_FRAME_RECORD tile_id_list, layout_list` records.
- Current uncommitted recovery also macro-structures the Bank 1 sprite layout
  streams with `SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr` records and named
  end/inherit attribute bits.
- Current uncommitted recovery also macro-structures the Bank 1 sprite object
  pointer table with `SPRITE_OBJECT_FRAME_TABLE object_type, frame_table`
  records and the 36 explicit sprite tile-id byte streams with count-specific
  `SPRITE_TILE_LIST_N` records.
- Current uncommitted recovery also macro-structures Bank 0 OAM templates with
  `OAM_TEMPLATE_ENTRY y, x, tile, attr` records for the pause overlay and
  matching animation templates.
- Current uncommitted recovery also macro-structures packed-BCD score-delta
  tables with `SCORE_DELTA_ENTRY` records for matching score bonuses and
  board-scan reward scores.
- Current uncommitted recovery also macro-structures the A-type round-complete
  reveal threshold table with `ROUND_COMPLETE_REVEAL_THRESHOLDS` records
  ordered by 500/200/100/50-point reveal gates.
- Current uncommitted recovery also macro-structures the A-type round-complete
  final tile table with `ROUND_COMPLETE_FINAL_TILE` records selected by
  `ANIM_FRAME`.
- Current uncommitted recovery also macro-structures the A-type round-complete
  summary tile strings as paired `ROUND_COMPLETE_SUMMARY_MESSAGE_HALF` records.
- Current uncommitted recovery also classifies the 2P pre-play master/slave
  initialization sound IDs `$6B/$6D` and aliases their sound-index table
  entries.
- Current uncommitted recovery also names the 1P countdown tile-slot
  coordinates/tile IDs, countdown blit timer reload, playfield digit
  mask/base/blank tile, and B-type round-timer separator tile.
- Current uncommitted recovery also names score display digit count, the
  `ResetScoreAccumulatorAndDigits` score clear span, and the `AddScore` BCD overflow cap
  constants.
- Current uncommitted recovery also applies the board/drop geometry constants
  consistently to draw/drop stepping: `BOARD_CELL_STRIDE`,
  `GRID_PIECE_TILE_WIDTH`, `DROP_ANIM_STATE_STRIDE`,
  `BOARD_DRAW_FIRST_COLUMN`, and `COLUMN_SPRITE_TOP_ROW_OFFSET`.
- Current uncommitted recovery also includes the final generated local-label
  cleanup in Bank 0/1: detached pre-play label tiles, result confirm/menu
  waits, link-mode status fills, A-type round-complete summary setup, reveal
  threshold branches, manual OAM bonus animation, and input-aware wait loops.
- Current uncommitted recovery also clarifies two low-level leftovers:
  `BGM_PREVIEW_UNUSED_PERIOD` is write-only in the current source, and the
  `UpdateFallAcceleration` level-3 fall-acceleration reload branch is
  unreachable because the preceding
  `< PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD` branch already catches the
  `PIECE_FALL_ACCEL_LEVEL3_VALUE` path.
- Current uncommitted recovery also clarifies additional low-confidence
  clear/write-only bytes: `EGG_COUNT_UNUSED_BYTE`,
  `LINK_UNUSED_STAGING_BYTE`, and `DROP_ANIM_UNUSED_GRID_ROW_TMP`.
- Current uncommitted recovery also names narrow `UpdateFallingPieceMotionAndLanding` constants:
  `SPRITE_OBJECT_UPDATE_CONTINUE`, `PIECE_FALL_SPRITE_Y_STEP`,
  `COLUMN_TOP_ROW_OVERFLOW_SENTINEL`, and the use of `BOARD_DRAW_FIRST_ROW` as
  the top-row game-over sequence check.
- Current uncommitted recovery also renames the single-player top-row overflow
  result entry to `ProcessSinglePlayerGameOverResult`, matching the preceding
  `RESULT_GAME_OVER_FLAG` write and direct `ProcessRoundResultAndEnterRoundEnd` call.
- Current uncommitted recovery also renames the result-rank helper to
  `ResolveResultRankPosition`; the name reflects that the 2P path resolves
  equal local/peer result codes, while the non-2P path returns the input rank
  unchanged.
- Current uncommitted recovery also renames the link-result confirm clear and
  game-over branches to `HandleLinkResultClearConfirmOutcome` and
  `HandleLinkResultGameOverConfirmOutcome`, matching the status-strip and
  score-area drawing side effects.
- Current uncommitted recovery also renames the link-result packet merge label
  to `QueueLinkResultPacketOutcome`, matching the decoded result-code handoff to
  `QueueRoundResult`.
- Current uncommitted recovery also renames the remaining link packet dispatcher
  branch tests to `DispatchReceivedLinkFieldCountPacket` and
  `DispatchReceivedLinkFieldRisePacket`, separating packet detection from the
  `ProcessLink*Packet` handlers.
- Current uncommitted recovery also renames the link-result mark-limit and
  screen-mode branches to `SetTerminalLinkResultFlagIfMarkLimitReached`,
  `DrawZeroResultMarksIfAny`, and `DispatchLinkResultScreenMode`.
- Current uncommitted recovery also applies `BOARD_CELL_STRIDE` to the direct
  landing, staged-payload, rotation lookahead/backtrack, landing counter,
  commit top-row, and board-scan row movements. The same pass names the level
  fall-delay table clamp, board-scan loop seed/BG refresh row, landing reset
  timer seed, and field-column effect frame arguments.
- Current uncommitted recovery also names narrow result-flow constants:
  `RESULT_FLOW_INACTIVE`, `RESULT_FLAG_SET`, zero/nonzero
  `ROUND_RESULT_CODE_*` values, `LINK_RESULT_PACKET_FLAG` / bit selectors,
  `LINK_RESULT_MARK_LIMIT`, `LINK_RESULT_TERMINAL_FLAG_CLEAR`, and
  `RESULT_RANK_NONE` / `RESULT_RANK_FIRST_PLACE`. The game-over zero-result and
  no-rank paths now have source comments where the byte-preserving `xor a`
  instructions are semantically meaningful.
- The same link packet cleanup also names `LINK_FIELD_COUNT_PACKET_BIT` and
  `LINK_FIELD_EVENT_BIT`, matching the existing count/event packet flag
  constants.
- Current uncommitted recovery also names narrow grid-piece draw constants:
  4x2 payload dimensions, the `$11` shadow BG-map row delta, the side-column
  clear tile, the draw row limit, and the commit guard at top-row `$10`.
- Current uncommitted recovery also includes sound command/pitch-slide helper
  cleanup: `DispatchSoundNonEndCommand`, `CheckSoundLoopJumpCommand`,
  `CheckSoundLengthEnvelopeCommand`, `CheckSoundExtendedCommand`,
  `UpdateSoundPitchSlide`, `UpdateSoundPitchSlideDescending`,
  `ClearSoundPitchSlideFlags`, and `InitSoundPitchSlideForNote`.
- Current uncommitted recovery also macro-structures the channel-4 board-scan
  step effect sequences at `SoundSequenceData_7e67..7ea9` as
  `SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE` records. The entries are selected by
  `SoundIndexEntry_BoardScanStep0..6` and vary only the explicit frequency-low
  operand.
- Current uncommitted recovery also macro-structures the remaining short
  channel-4 sweep/extended-note effect sequences with `SOUND_SWEEP`,
  `SOUND_DUTY_LENGTH`, `SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END`
  records.
- Current uncommitted recovery also macro-structures the tail-adjacent
  extended-note sequences at `SoundSequenceData_7f0d`, `7fb4`, `7fd0`, and
  `7fe3`, preserves the shared end-only labels at `7f1b` and `7fc2`, rewrites
  the adjacent channel-7 streams at `7f1c` and `7fc3` as
  `SOUND_CHANNEL7_EXTENDED_NOTE` records, exposes the gate/length-envelope/
  octave/pitch-slide tails at `7f65` and `7f80`, and splits the final
  `01:$7FF6-$7FFF` filler as `Bank1TailPaddingData`.
- Current uncommitted recovery also macro-structures `SoundSequenceData_7e15`,
  the channel-5 half of the pause sound pair, while keeping the channel-4
  `SoundSequenceData_7dff` bytes raw because that address is also a wave
  pattern pointer target.
- Current uncommitted recovery also macro-structures `TitleBgmChannel2Sequence`
  as one `SOUND_LENGTH_ENVELOPE` command and four `SOUND_SUBSEQUENCE_CALL`
  records targeting `SoundSequenceData_5a34`.
- Current uncommitted recovery also macro-structures the high-confidence setup
  commands in `TitleBgmChannel1Sequence` as duty/length, vibrato,
  length/envelope, and octave records, leaving note bytes raw.
- Current uncommitted recovery also macro-structures `TitleBgmChannel3Sequence`
  and its `SoundSequenceData_5a89` loop as channel-3 length-scale, rest,
  nested-sound note, and unconditional loop records.
- Current uncommitted recovery also macro-structures the `BgmOption0*` and
  `BgmPreview0*` channel heads with generic setup, rest-note, octave,
  visual-update, and frequency-carry command records.
- Current uncommitted recovery also macro-structures the BGM preview 0
  channel-3 visual-update loop labels `MusicSequenceData_60ce` through
  `MusicSequenceData_6158` with generic visual-update, rest-note, length-scale,
  and loop records.
- Current uncommitted recovery also macro-structures the `BgmOption1*` and
  `BgmPreview1*` channel heads with the same generic command-record style,
  adding vibrato records where those channel heads include `$EA` commands.
- Current uncommitted recovery also macro-structures the BGM preview 1
  channel-3 visual-update loop labels `MusicSequenceData_64f0` through
  `MusicSequenceData_656e` with the same generic command-record style.
- Current uncommitted recovery also macro-structures the `BgmOption2*` and
  `BgmPreview2*` channel heads with the same generic command-record style,
  completing the first pass over the three BGM option/preview head groups.
- Current uncommitted recovery also macro-structures the BGM preview 2
  channel-3 visual-update loop labels `MusicSequenceData_6b2a` through
  `MusicSequenceData_6c9b` with the same generic command-record style.
- Current uncommitted recovery also names the `MatchingTileBaseIndexTable`
  entries as `MATCHING_TILE_BASE_INDEX_STATE_0..27`. The names are scoped to
  the `STATE_TRANSITION` index values because the same byte is later scaled
  differently for the middle four-OAM group and the final two-OAM pair.
- Current uncommitted recovery also includes drop-animation cascade loop label
  cleanup: `AnimateDropDownCascadeLoop`, `AdvanceDropDownCascadeSlot`,
  `AnimateDropUpCascadeLoop`, and `AdvanceDropUpCascadeSlot`.
- Current uncommitted recovery also includes drop-animation completion/swap
  local cleanup: `BeginDropDownCascade`, `CheckDropDownCascadeEnd`,
  `BeginDropUpCascade`, `CheckDropUpCascadeEnd`,
  `FinishDropCascadeAndSwapColumns`, `SwapDropAnimationColumnCellsLoop`, and
  `SwapColumnTopRowsAfterDrop`.
- Current uncommitted recovery also includes drop collision/update local
  cleanup: `ScanDropCollisionSpriteSlotsLoop`,
  `SkipInactiveDropCollisionSlot`, `AdvanceDropCollisionSlot`,
  `ReturnDropCollisionDetected`, `UpdateDropPositionsLoop`, and
  `AdvanceDropPositionSlot`. The same path now names the grid-column unset
  sentinel, collision X step, row-overlap limit, and active-state clear span.
- Current uncommitted recovery also includes drop down/up state local cleanup:
  state-check, redraw, boundary, clear-loop, and return labels inside
  `AnimateDropDown`, `AnimateDropUp`, `ClearDropAnimationState`, and
  `StartDropColumnSwapAnimation`.
- Current uncommitted recovery also includes the unreferenced
  `UnusedFillBoardDataPattern` fragment and `UpdateColumnBlinkState` slot-loop
  cleanup.
- Current uncommitted recovery also includes Bank 0 local control label cleanup:
  `CopyOAMDMARoutineToHRAMLoop`, `StoreDisabledLCDCAndRestoreIE`,
  `CheckPauseAllowedForLinkMaster`, `CheckPersistMagicByte1`,
  `ClearColumnLeftNextTilemapPage`, `UpdateFieldAnimSlot11BaseY`, and
  `HandleSinglePlayerRoundCompleteFlow`.
- Current uncommitted recovery also renames the stale
  `SetupMultiplayer` field-animation dispatcher to
  `UpdateFieldAnimationSlots`, matching the four `UpdateFieldAnimSlot*` calls
  it performs.
- Current uncommitted recovery also includes Bank 0 initial utility loop
  cleanup: `WaitJoypadLinesReleasedLoop`, `WaitForLCDOffSafeLine`,
  `ClearShadowOamLoop`, `HideShadowOamSpritesLoop`, and
  `CopyBytesDuplicatedLoop`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with those
  recovered low-level helper labels, including the joypad reset wait,
  OAM-DMA HRAM copy loop, LCD-off restore tail, shadow-OAM loops, and
  duplicate-byte copy loop.
- Current uncommitted recovery also names the low-level joypad P1 poll masks,
  OAM DMA HRAM copy size/address byte, and LCD-off safe-line/disable mask
  immediates in the Bank 0 utility path.
- Current uncommitted recovery also applies those joypad P1 constants to the
  Bank 1 `CheckJoypadRaw` direct button-line poll.
- Current uncommitted recovery also names the Bank 1 `HandleWaveUpdate` wave
  RAM end, channel-3 terminal output bits, trigger value, terminal clear mask,
  and code-byte end marker constants.
- Current uncommitted recovery also names Bank 1 sound vibrato/duty packed
  masks and `SoundUpdate3` register offsets for NRx1/NRx2/NRx3 writes.
- Current uncommitted recovery also applies `SOUND_COUNTER_INIT_VALUE` to the
  `$FE` loop/jump command's counted-loop reset path.
- Current uncommitted recovery also names the Bank 1 sound pause mute-applied
  flag bit, NR30 wave enable/disable values, silent-rest envelope value, and
  NRx4 restart/high-frequency mask.
- Current uncommitted recovery also names the Bank 1 sound note-length parser
  step value, wave-level parameter bits, and selected wave-pattern copy loop
  index.
- Current uncommitted recovery also names the Bank 1 `SoundUpdate5`
  pitch-table shift target and high-byte bias constants.
- Current uncommitted recovery also names the 12 `SoundPitchBaseTable` entries
  as `SOUND_PITCH_BASE_INDEX_0..11`, keeping them tied to the low-nibble note
  index consumed by `SoundUpdate5` rather than assigning unproven note letters.
- Current uncommitted recovery also names the four direct `SND_TITLE_BGM`
  sequence targets as `TitleBgmChannel0Sequence` through
  `TitleBgmChannel3Sequence`, while leaving internal music-stream joins
  address-based.
- Current uncommitted recovery also names the direct `BgmOption0..2` and
  `BgmPreview0..2` channel sequence targets, again leaving internal
  music-stream joins address-based.
- Current uncommitted recovery also names the direct link-role, confirm, and
  link-result channel sequence targets, including the shared link-role channel
  0 stream.
- Current uncommitted recovery also names the direct 1P result, 2P result, and
  2P preplay-init channel sequence targets.
- Current uncommitted recovery also macro-structures the 1P result channel
  heads with generic setup, rest-note, octave, vibrato, frequency-carry, and
  sequence-end command records.
- Current uncommitted recovery also macro-structures the 2P result channel
  heads with generic setup, rest-note, octave, pitch-slide, frequency-carry,
  and sequence-end command records.
- Current uncommitted recovery also macro-structures the 2P preplay-init
  channel setup command bytes while leaving pitch/duration bytes raw.
- Current uncommitted recovery also macro-structures the 2P preplay-init
  phrase labels with generic length/envelope, octave, and loop command records.
- Current uncommitted recovery also macro-structures the link field-rise sound
  stream with generic gate-flag, duty/length, length/envelope, octave,
  extended-note, pitch-slide, and sequence-end command records.
- Current uncommitted recovery also names the Bank 1 fixed `$0100` tempo
  multiplier for channel 7 and the one-tick pitch-slide clamp.
- Current uncommitted recovery also names the Bank 1 sound BGM-reset command
  bounds and primary-channel clear spans.
- Current uncommitted recovery also names the Bank 1 sound hardware reset
  register values and full reset clear spans.
- Current uncommitted recovery also names the Bank 1 sound register base lows
  used by `SoundRegisterOffsetTable` and the channel-6 sequence-pointer offset
  used when low-ID BGM active state points channel 6 at `SoundWaveDutyData`.
- Current uncommitted recovery also macro-structures the Bank 1 sound support
  tables with `SOUND_WAVE_DUTY_END`, `SOUND_REGISTER_OFFSET_ENTRY`,
  `SOUND_CHANNEL_MASK_ENTRY`, and `SOUND_PITCH_BASE_ENTRY` records.
- Current uncommitted recovery also names the Bank 1 sound sequence-pointer
  rewind constants used by the BGM active-ID gate.
- Current uncommitted recovery also names the Bank 1 `SOUND_BGM_ACTIVE_ID`
  low-ID gate used by NR50 restore, sequence rewind, channel-7 priority, and
  BGM active-state setup.
- Current uncommitted recovery also includes Bank 0 startup clear loop cleanup:
  `UseFullWRAMClear`, `BeginWRAMClear`, `ClearWRAMLoop`,
  `ClearWRAMByte`, `ClearVRAMLoop`, and `ClearHRAMWorkAreaLoop`, plus the
  startup WRAM clear-mode constants for preserving or clearing result records.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with those startup
  clear labels and the recovered hardware tilemap fill helpers
  `BeginHardwareTilemapFill` / `FillHardwareTilemapLoop`.
- Current uncommitted recovery also names startup hardware initialization
  constants for palettes, stack top, HRAM clear size, enabled interrupts,
  offscreen window Y, window X, hardware tilemap pages, tilemap clear size/tile,
  and final LCDC flags.
- Current uncommitted recovery also includes Bank 0 tilemap fill loop cleanup:
  `BeginBgMapShadowFill`, `FillBgMapShadowLoop`,
  `BeginHardwareTilemapFill`, and `FillHardwareTilemapLoop`.
- Current uncommitted recovery also names the game/title BG-map shadow clear
  tiles used by `FillGameTilemap` and `FillTitleTilemap`.
- Current uncommitted recovery also includes Bank 0 tilemap address calculation
  local cleanup: `AddTilemapColumnOffset`, `AddBgMapShadowBaseLow`, and
  `StoreCalculatedTilemapAddressLow`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  Bank 0 BG-map fill and tilemap-address utility labels, replacing stale
  `FillOAMGameTile`, `FillOAMTitleTile`, and `CalcOAMAddress` names.
- Current uncommitted recovery also includes Bank 0 MainLoop and pause local
  cleanup: state dispatch labels, `PlaySinglePlayerSelectedBgm`,
  `InitPlayfieldAfterBgmSetup`, `IgnoreInvalidGameStateAndLoop`,
  `StoreGameStateAndLoop`, `RestoreMainBankAfterGameTileLoad`, `CheckPauseButtonInput`,
  `WaitPauseResumeInputLoop`, `PlayPauseSoundAndHalt`, and
  `WaitLinkPeerUnpauseLoop`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  VRAM copy chunk-loop labels, MainLoop dispatch labels, graphics-bank restore
  tail, and pause helper labels.
- Current uncommitted recovery also names the three BG-map shadow copy phase
  values used by the VBlank `CopyNextBgMapShadowSlice` path.
- Current uncommitted recovery also includes game-state init and drop cursor
  local cleanup: `InitSinglePlayerLevelSpeedSettings`,
  `InitTwoPlayerLevelSpeedSettings`, `AdvanceDropCursorAltFrame`,
  `StoreAdvancedDropCursorFrame`, and `StopDropCursorFrameAnimation`.
- Current uncommitted recovery also includes Bank 0 masked random-count and
  sprite-object local cleanup: `MultiplyShiftMultiplierLoop`,
  `AddShiftedMultiplicandToProduct`, `ShiftMultiplicandForNextBit`,
  `CountMaskedMultiplyBitsLoop`,
  `ContinueMaskedMultiplyBitCount`, `TickSpriteObjectWaitPhase`, and
  `WriteBackSpriteObjectStaging`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  Bank 0 math and sprite-object helper labels, including
  `MultiplyAddCarryChain` and the conditional sprite-row advance labels.
- Current uncommitted recovery also names the Bank 1 sprite object renderer
  scan-end offset used when the 16-slot `$C2xx` scan wraps its low byte to zero.
- Current uncommitted recovery also includes Bank 0 tile-sprite and board draw
  local cleanup: conditional four-byte sprite row advance labels,
  `DrawGridPieceWithinBounds`, `DrawGridPieceSecondRow`,
  `ClearColumnLeftLoop`, `ClearColumnRightLoop`,
  `DrawAllColumnsColumnLoop`, `DrawAllColumnsRowLoop`, and
  `AdvanceDrawAllColumnsColumn`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  column-sprite, grid-piece, column-clear, and all-column draw helper labels
  already present in `Yoshi/bank_000.asm` and rebuilt `Yoshi/game.sym`.
- Current uncommitted recovery also includes Bank 0 column blink sprite draw
  local cleanup: `ReadColumnTopRowForSprite`, `DrawColumnSpriteRow0..2`, and
  the static-dead alternate-row fragment inside `DrawColumnSprite`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  Bank 0 drop cascade, collision scan, drop-position update, drop-down/drop-up
  state, and clear-animation helper labels already present in source and
  rebuilt `Yoshi/game.sym`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  `StartDropColumnSwapAnimation` return label, unused board-pattern helper
  labels, column blink slot-scan helper labels, and game-state
  init/drop-cursor helper labels.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  `ProcessMatching` / result-panel helper labels, including matching intro
  blink loops, OAM slide loops, result-panel edge fill, final OAM move, and
  matching score digit loops.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  gameplay update, playfield input, falling-piece, B-type init, initial board
  fill, rotation, landing-progress, board-scan, and timer helper labels already
  present in source and rebuilt `Yoshi/game.sym`.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  round-transition send loop, round-complete result tables, piece-display state
  builders, game-turn/menu selection helpers, field-occupancy scan, forced-state
  application, pending-field-rise, and piece-display blink helper labels. The
  stale `DrawTextBox` / `DrawTextString` / `ClearTextArea` labels at
  `00:$1BD0-$1BFD` were corrected to the recovered blink routines.
- Current uncommitted recovery also names the title/preplay level preview digit
  coordinate as `TITLE_LEVEL_PREVIEW_DIGITS_COORD`, an alias of the A-type
  playfield level digit coordinate used by the same two-digit renderer.
- Current uncommitted recovery also names the title-screen BG layout fill tile
  bases used by `InitTitleUI`, complementing the already recovered title
  rectangle origins and sizes.
- Current uncommitted recovery also names the serial completion active value,
  the unassigned-role title ready byte comparison, the unassigned-role `rDIV`
  reset write value, and the two-slot link send queue wrap count.
- Current uncommitted recovery also names the title-reset write-only `$FF94`
  HRAM flag and the initial value stored to the adjacent unused title marker
  delay byte.
- Current uncommitted recovery also names the Bank 0 `Multiply` RNG HRAM state,
  work bytes, multiplier bytes, and increment bytes used by the local shift/add
  update loop.
- Current uncommitted recovery also names the adjacent visible board-cell delta
  used by landing, B-type initial-fill duplicate avoidance, and board-scan target
  probing inside the two-byte board row-cell layout.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with the recovered
  option UI text/table labels, option marker branches, settings cursor init
  data, detached preplay input branches, BGM preview settings branches, option
  cursor highlight triplets, option value drawing branches, and serial
  interrupt tail labels.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with recovered
  title string copy/run-menu labels, 2P preplay init labels, and field
  animation slot step/end labels. Stale `InitGameVars`, `Setup2PField`,
  `SetupLinkCable`, and `DrawField*` labels in the `00:$215B-$22A9` range were
  corrected to the recovered source names.
- Current uncommitted recovery also syncs `Yoshi/yoshi.sym` with recovered 2P
  preplay role/speed text blocks, level-preview text table labels, 2P settings
  exchange labels, and result-record initialization labels. The same-address
  `PiecePreviewText0` / `PiecePreviewTextTable` alias is represented by
  `PiecePreviewTextTable` in `Yoshi/yoshi.sym` to keep duplicate-label audits
  clean.
- Current uncommitted recovery also macro-structures the Bank 0
  `PiecePreviewTextTable` rows as selected/unselected preview cells with named
  level digit tiles.
- Current uncommitted recovery also macro-structures the Bank 0 preplay speed
  text blocks as `PREPLAY_SPEED_TEXT_ROW` records with a named panel-clear gap.
- Current uncommitted recovery also macro-structures the Bank 0 two-player
  role header text with `TWO_PLAYER_ROLE_HEADER_TEXT` and named suffix tiles.
- Current uncommitted recovery also macro-structures the Bank 0 BGM marker text
  rows with a named width and selected-marker offsets for options 0/1/2/off.
- Current uncommitted recovery also macro-structures the Bank 0 countdown digit
  bitmap table as ten `COUNTDOWN_DIGIT_PATTERN` records.
- Current uncommitted recovery also macro-structures the Bank 0 1P preplay
  header text rows with `PREPLAY_HEADER_TEXT_ROW_*` records.
- Current uncommitted recovery also macro-structures the duplicate Bank 0
  preplay `OFF` text as an `OPTION_TEXT_ROW_3` record.
- Current uncommitted recovery also macro-structures the Bank 0 1P preplay
  game-type text rows with paired `PREPLAY_GAME_TYPE_TEXT_ROW_START` /
  `PREPLAY_GAME_TYPE_TEXT_ROW_END` records.
- Current uncommitted recovery also removes the final anonymous `Jump_*` labels
  from Bank 0/1 real code with `ResetJoypadStateAndReinitOnRelease`,
  `MultiplyAddCarryChain`, and `ExpandSoundIndexChannelEntryLoop`.
- Current uncommitted recovery also includes result-record staging/insert/screen
  local label cleanup: `CopyATypeEggCountRemainingDigits`,
  `CopyBTypeResultTimerDigits`, `MaskCurrentResultRecordDigits`,
  `ScanResultRecordInsertPositionLoop`, `CompareBTypeResultTimerDigits`,
  `AdvanceResultRecordScanSlot`, `InsertCurrentResultRecordAtRank`,
  `ShiftBTypeResultRecordsForInsert`, `CopyCurrentResultRecordToRankSlot`,
  `SetupResultRecordScreen`, and `FillResultRecordBoxBodyRows`.
- Current uncommitted recovery also includes result-record rendering/palette
  helper cleanup: `DrawBTypeResultRecordDetailLayout`,
  `RenderStoredResultRecords`, `RenderBTypeResultRecords`,
  `WaitResultRecordScreenInput`, `BlinkResultRecordLabelLoop`,
  `DrawResultRecordLabelBlinkState`, `PollResultRecordBlinkInput`,
  `FillResultRecordPlaceholderColumnLoop`, `CompareResultRecordBytes`,
  `DrawStoredResultRecords`, `DrawResultRecordDigitRun`,
  `FillResultRecordBoxRowMiddleLoop`, `FadeInResultRecordPalette`, and
  `ResultRecordPaletteSequence`.
- Current uncommitted recovery also names the result-record inserted-row label
  blink timing: `RESULT_RECORD_LABEL_BLINK_ALT_START_FRAME` and
  `RESULT_RECORD_LABEL_BLINK_PERIOD`.
- Current uncommitted recovery also names the `DrawScoreRanking` rank display
  origins, tile-run length, top/bottom tile bases, and special-position
  normalization constants.
- Current uncommitted recovery also includes 1P pre-play input branch cleanup:
  `Handle1PPreplayNonStartInput`, `Move1PPreplayCursorUp`,
  `Move1PPreplayCursorDown`, `Increment1PPreplaySelectedOption`,
  `Decrement1PPreplaySelectedOption`, and `PreplayLoopOptionCountTable`. The
  detached/live 1P pre-play direction tests now use `PADB_UP`, `PADB_DOWN`,
  `PADB_RIGHT`, and `PADB_LEFT`. The detached label-tile tail after
  `BgmMarkerNoneText` now reuses the shared pre-play level-label tile-row
  constants and `PREPLAY_LABEL_TILE_ROW_WIDTH`. The former `DrawCountdownNum`
  helper is now named
  `ClearSettingsCursorFrameHighBits` because it normalizes settings cursor
  sprite frames, not countdown digits. `ApplySettings` now names the
  settings-cursor init record copy size, frame values, shared base Y, unused
  bytes, and three base-X positions; the three init rows now use
  `SETTINGS_CURSOR_INIT_RECORD`. `OptionTextAGame` through
  `OptionTextOff` now use `OPTION_TEXT_ROW_N` records and `OPTION_TEXT_TILE_*`
  constants. `OptionMarkerPositions` now emits `OPTION_MARKER_POSITION`
  records derived from the selected-marker coordinate constants. The option
  cursor triplet data labels now distinguish inactive and per-row highlight
  triplet lists, with each tuple emitted by `DRAW_TILE_TRIPLET`.
- Current uncommitted recovery also names the normal/selected option box
  frame-tile offsets and replaces the option redraw path's remaining raw cursor
  row, level value, and BGM value comparisons with option constants.
- Current uncommitted recovery also renames the option box drawing helpers from
  generic `DrawLabel` / `SetPalette` / `TileDataLookup*` names to behavior
  names for the neutral layout, level-value boxes, shared box renderer, and
  individual option boxes.
- Current uncommitted recovery also names the option decoration strip, option
  box frame tile bases, individual option box coordinates, and the inner
  row/width values used by the shared option box renderer.
- Current uncommitted recovery also renames the 1P option-count tables, names
  the four option counts used as exclusive upper bounds for game type, level,
  speed, and BGM rows, and structures their entries with
  `PREPLAY_OPTION_COUNT_ENTRY`.
- Current uncommitted recovery also names the 1P option cursor row constants,
  detached cursor wrap sentinel, BGM-off option value, and the `OPTION_BGM`
  low-byte comparison used by the detached option redraw path.
- Current uncommitted recovery also includes 2P pre-play input branch cleanup:
  `Check2PPreplayReceivedStartHandshake`,
  `Poll2PPreplayNonMasterInput`, `Enter2PPreplayPlaySetup`,
  `Handle2PPreplayNonStartInput`, `Move2PPreplayCursorUp`,
  `Move2PPreplayCursorDown`, `Increment2PPreplaySelectedSetting`, and
  `Decrement2PPreplaySelectedSetting`. The 2P direction tests now use the
  matching `PADB_*` constants.
- Current uncommitted recovery also replaces remaining Start-button raw bit/value
  tests with `PADB_START` / `PADF_START`, names the `$01` link-role
  comparisons/stores as `LINK_ROLE_MASTER`, and names common link serial
  transfer/confirm/pause bytes.
- Current uncommitted recovery also includes 1P pre-play screen drawing helper
  cleanup, replacing misleading win/lose-style labels with
  `Draw1PPreplayBackground`, `Draw1PPreplayHeaderText`,
  `Draw1PPreplayGameTypeLabel`, `Draw1PPreplayLevelLabel`,
  `Draw1PPreplaySpeedLabel`, `Draw1PPreplayBgmLabel`,
  `Draw1PPreplayLevelText`, `Draw1PPreplaySpeedText`,
  `Draw1PPreplayGameTypeText`, `Draw1PPreplayBgmOffText`, and
  `Draw1PPreplayBgmMarker` plus their local selection branches. The 1P
  pre-play background fill and option panel rectangles now use named layout
  constants, and the 1P pre-play label/text coordinates plus shared
  level/speed label tile rows are now named. `PREPLAY_LABEL_TILE_ROW_WIDTH`
  names the shared four-tile label width used by the 1P, 2P, and detached
  pre-play label paths. The BGM marker string data now uses the shared option
  marker tile constants.
- Current uncommitted recovery also includes 2P pre-play screen drawing helper
  cleanup: `Init2PPreplayBlinkTimer`, `Draw2PPreplayScreen`,
  `Draw2PPreplayDynamicSettings`, `Draw2PPreplayRoleHeader`,
  `Draw2PPreplayRolePanels`, `Draw2PPreplayLevelText`, and
  `Draw2PPreplaySpeedText` plus their local selection branches. The 2P
  pre-play background fill and upper/lower setup panel rectangles now use named
  layout constants, and the 2P level/speed label paths reuse the shared
  pre-play label tile-row constants and `PREPLAY_LABEL_TILE_ROW_WIDTH`. The 2P
  role header, role-panel tile bases, local/peer level preview coordinates, and
  local/peer speed text coordinates are now named.
- Current uncommitted recovery also includes 2P link packet/result exchange
  cleanup: `SendNextLinkQueueByte`, `DispatchReceivedLinkPacket`,
  `ProcessLinkFieldRisePacket`, `ProcessLinkResultPacket`, and
  `Exchange2PResultCode`.
- Current uncommitted recovery also includes field timer and 2P field-count
  loop cleanup: `UpdateFieldColumnTimerLoop`,
  `ClearSpriteObjectSlotLoop`, `CountLinkFieldTensDigitLoop`,
  `ScanLinkFieldOccupancyRow`, and `ScanLinkFieldOccupancyColumn`.
- Current uncommitted recovery also includes Bank 1 sprite OAM expansion loop
  cleanup: `BeginSpriteOamExpansion`, `ScanSpriteObjectSlotLoop`,
  `DrawSpriteObjectOamEntryLoop`, `StoreSpriteObjectOamAttributes`,
  `AdvanceSpriteObjectSlot`, and `HideUnusedShadowOamLoop`.
- Current uncommitted recovery also includes Bank 1 countdown/score/playfield
  local loop cleanup: `Draw1PCountdownDigitTileSlots`,
  `DrawCountdownDigitTileSlotTail`, `UnusedDrawLowNibbleTileDigitsLoop`,
  `ClearScoreAccumulatorAndDigitsLoop`, `UseBlankUnusedBcdTensTile`,
  `ContinueGameMainAfterTimerDraw`, `FillGameplayBgTopRowLoop`, and
  `CopyFieldColumnTilePatternLoop`.
- Current uncommitted recovery also names the Bank 1 game BG top-row fill
  coordinate/width/tile, corrects `FieldColumnTilePatternTable` to three
  16-byte records, and names the field-column pattern record size/count/index
  shift/destination plus the next-round active-level max.
- Current uncommitted recovery also macro-structures `FieldColumnTilePatternTable`
  as six `FIELD_COLUMN_TILE_PATTERN_ROW` rows using blank/marker tile roles.
- Current uncommitted recovery also includes Bank 1 next-round/tilemap helper
  local cleanup: `SetupNextRoundSinglePlayerSettings`,
  `SkipNextRoundActiveLevelIncrement`, `ContinueNextRoundSetup`,
  `FillTilemapRectRowLoop`, `FillTilemapRectColumnLoop`,
  `AdvanceTilemapRectRow`, and `DrawSequentialTileRowLoop`. The shared
  rectangle helper now uses `BG_MAP_ROW_STRIDE` for its row advance.
- Current uncommitted recovery also includes Bank 1 level/egg display local
  cleanup: `IncrementATypeLevelDisplayDigits`,
  `StoreATypeLevelDisplayOnes`, `IncrementLevelDisplayDigits`,
  `StoreLevelDisplayOnes`, `UseEggTextFrame0..2`,
  `DrawEggTextFrameRows`, `DrawPlayfieldEggCountDigitsAtCoord`, and
  `RefreshEggCountDigitsAfterIncrement`. The current source also names the
  level-display digit limit/max and the A/B-type egg text/count packed
  coordinates.
- Current uncommitted recovery also labels the unreferenced
  `01:$45C6-$45EF` inline egg-text writer as
  `UnusedInlineEggTextFrame0Drawer` and names the egg-text animation frame
  constants used by the pulse/alternate animation paths. The unused inline
  writer and the live frame-0 tile rows now share `EGG_TEXT_FRAME0_TILE_BASE`
  and explicit inline row-delta constants.
- Current uncommitted recovery also macro-structures the live Bank 1
  `EggTextFrame0..2TileRows` data with `EGG_TEXT_TILE_ROW_N` records, frame
  tile-base constants, and the named side-panel fill tile.
- Current uncommitted recovery also includes slot-0 player cursor seed
  constants for the field-column tile pattern index, initial cursor frame,
  base Y, and base X.
- Current uncommitted recovery also includes Bank 1 title marker/link local
  cleanup: `SelectTitleTwoPlayerMode`, `SelectTitleOnePlayerMode`,
  `ToggleTitlePlayerMode`, `DrawTitlePlayerSelectionMarker`,
  `PollTitleStartOrReceivedLink`, `HandleTitleLinkHandshakeByte`,
  `EnterPreplayInitFromTitle`, and `TickTitlePlayerMarkerBlink`. The current
  source also names the title label-row marker coordinates/tiles, marker blink
  durations, player-mode bounds/toggle/underflow values, title input button
  bits, and title-link start/ready handshake bytes.
- Current uncommitted recovery also macro-structures the Bank 1 title label
  text rows with `TITLE_LABEL_TEXT_ROW`, per-row prefix-tile constants, the
  title-label separator tile, and the shared six-tile suffix base.
- Current uncommitted recovery also includes Bank 1 egg text pulse and BG map
  shadow-copy local cleanup: `DrawEggTextPulseFrame2`,
  `ToggleEggTextPulseFrame`, `ReturnAfterEggTextPulseComplete`,
  `SelectBgMapShadowCopySlice0`, `SelectBgMapShadowCopySlice1`,
  `StoreNextBgMapShadowCopyPhase`, and `CopyBgMapShadowSliceRowLoop`.
- Current uncommitted recovery also includes Bank 1 VBlank/VRAM copy local
  cleanup: `CopyQueuedVram16ByteBlockLoop`, `CheckVBlankBusyCounter`,
  `ContinueVBlankRuntimeUpdates`, `ContinueVBlankAfterWaveUpdate`,
  `ReturnFromVBlankHandler`, `WaitVBlankSyncLoop`, and
  `WaitJoypadStartOrSelectPressLoop`.
- Current uncommitted recovery also restores the executable Bank 1 wait-loop
  `$76` bytes to explicit `halt` instructions in those wait loops.
- Current uncommitted recovery also names the Bank 1 VBlank sync request value,
  the static-dead Select-gated wait helper at `01:$4BD0`, and its
  Select/Start-or-Select joypad masks.
- Current uncommitted recovery also names the Bank 1 `UpdateSprites` redraw
  hide-all sentinel and the sprite-object disabled-frame sentinel.
- Current uncommitted recovery also names the `ClearSpriteObjectBuffer`
  byte count as `SPRITE_OBJECT_BUFFER_CLEAR_BYTES`.
- Current uncommitted recovery also includes Bank 1 playfield HUD
  coordinate-selection local cleanup: mode-specific level/speed/egg display
  packed-coordinate constants, shared draw targets, and the currently
  unreferenced `UnusedDrawPlayfieldGameTypeHeader` fragment.
- Current uncommitted recovery also includes Bank 1 VBlank sound/timer local
  cleanup: `HandleWaveUpdate`, `UpdateElapsedTimers`,
  `TickElapsedTimerDigits`, `UpdateSoundChannels`, `TickSoundChannel`, and
  local sound delay/vibrato branch names, plus named elapsed-timer digit
  bounds and the 99:59 clamp constants.
- Current uncommitted recovery also includes Bank 1 sound sequence parser local
  cleanup: `$FF` end/return branches, `$FE` loop target branches,
  `$D0-$DF` wave/envelope storage branches, `$E8/$EA/$EB`
  vibrato/pitch-slide checks, and `$EC/$ED/$EE/$EF/$FC/$F0`
  duty/tempo/output/nested-sound/master-volume checks, plus the `$F1`
  `SOUND_VISUAL_UPDATE_COMMAND`, `$F8` `SOUND_GATE_FLAG_COMMAND`,
  `$E0`, and first note/sweep/channel-3 nested-sound checks. The parser compare
  sites now use named command-byte constants such as
  `SOUND_SUBSEQUENCE_CALL_COMMAND`, `SOUND_LOOP_JUMP_COMMAND`,
  `SOUND_VIBRATO_COMMAND`, and `SOUND_MASTER_VOLUME_COMMAND`.
- Current uncommitted recovery also names the observed `SOUND_CH_FLAGS` bit
  roles: frequency carry, return-pending, note-output gate, vibrato subtract
  phase, pitch-slide active/descending state, and duty-rotate active state.
- Current uncommitted recovery also names the sound parser/setup channel-index
  constants for the primary split, last channel, primary/secondary wave
  channels, and channel-3 branch.
- Current uncommitted recovery also includes Bank 1 sound note/output local
  cleanup: `ProcessSoundNoteCommand`, tempo selection, rest handling,
  pitch-slide note initialization, output-mask application, and sound-channel
  length-register write branches.
- Current uncommitted recovery also includes Bank 1 `ProcessNote`,
  pitch-slide, `SoundUpdate*`, and `SoundLookupIndex` local cleanup: wave RAM
  pattern copy, `SOUND_WAVE_PATTERN_POINTER` records,
  `SOUND_WAVE_PATTERN_ROW` records for the three dedicated waveforms,
  `SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE` records for the early channel-7
  effects, `SOUND_CHANNEL7_EXTENDED_NOTE` records for the two tail-adjacent
  channel-7 streams, generic `SOUND_DUTY_LENGTH` / `SOUND_SWEEP` /
  `SOUND_EXTENDED_NOTE` records for 13 short effect sequences, generic
  gate/length-envelope/octave/pitch-slide records for the `7f65` / `7f80` tail
  streams, frequency trigger writes, pitch-slide frequency/step storage,
  register-pointer and multiply
  helpers, BGM-range reset, sound-channel priority checks, new-entry state
  clear, and the generic sound-state fill loop.
- Current uncommitted recovery also includes Bank 1 `StartSoundSequence` local
  cleanup and symbol-boundary sync: sequence-pointer slot search, channel entry
  installation, BGM active-state setup, `rNR50` backup, and `Yoshi/yoshi.sym`
  sound setup/sequence/index/wave/tail boundaries now match the recovered
  source ranges. Shared sound reset defaults now name the `$01`
  counter/length/tempo seed, `$FF` output mask, and `$77` `rNR50` reset value.
- Current uncommitted recovery also expresses the `SoundIndexTable` as
  `SOUND_INDEX_ENTRY` records. `SOUND_INDEX_ENTRY_COUNT_1..4` name the number
  of adjacent entries expanded for a sound start, and
  `SOUND_INDEX_ENTRY_CHANNEL_0..7` name the channel slot selected by the low
  nibble. The all-`$FF` entry `$00` now uses explicit sentinel flags/pointer
  constants while remaining unconfirmed as a playable sound ID.
- Current uncommitted recovery also syncs the active `Yoshi/ARCHITECTURE.md`
  overview with recovered labels and data shape. Old placeholder names such as
  `ProcessGameTurn`, `CheckMatch`, `DisplayScore`, `MusicDataInit`, and
  `ProcessFieldLogic` are replaced with current labels like
  `UpdateGameplayObjectsAndCheckBTypeClear`,
  `UpdateFallingPieceMotionAndLanding`, `GameTurnParamTable`,
  `SoundSequenceStep`, and `CopyNextBgMapShadowSlice`. The board overview now
  describes `BOARD_DATA` as four 16-byte column blocks with odd-byte visible
  payload cells instead of a row-major 4x7 array.

## Remaining Work

### Immediate Next Chunks

- Revisit the `UNRESOLVED_LANDING_*` constants only after finding stronger
  producer/consumer evidence. They are documented as unresolved landing/scan
  bytes in `fall_timing.md`; the latest all-source and recent-history search
  found no hidden producer.
- Continue replacing any future raw tilemap offsets with named screen-region
  constants only where a repeated layout role is clear.
- Keep `SCORE_PRESERVED_UNUSED_BYTE` and `SCORE_UNUSED_TILE_BASE_*` low
  confidence until a consumer is found. They are touched around score/init code,
  but the current scan shows no independent read of the copied/swapped bytes and
  only preserve/restore behavior for `$C620`. The observed `$30` seed is now
  named `SCORE_UNUSED_TILE_BASE_INITIAL`.
- Keep `SPRITE_OBJECT_TOGGLED_FRAME` scoped to the option BGM cursor frame
  toggle and `SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE` scoped to the Down-held clamp
  path until another consumer appears. `SPRITE_OBJECT_UNUSED_1` remains
  padding/unused in the current trace, with only its observed template seed
  named as `SPRITE_OBJECT_UNUSED_1_INIT_VALUE`.
- Keep `SPRITE_OBJECT_TYPE_RESERVED_7` scoped to the existing type-$07 frame
  table entry until a producer is found. High-bit variants `$81-$87` are
  renderer-supported attribute aliases of `$01-$07`, but no current producer
  writes high-bit type bytes.

### Optional Future Refinement

- Map exact player-visible identities for any still-ambiguous piece payload
  values if independent evidence appears.
- Decode more sound/music command semantics beyond the behavior names already
  recovered.
- Expand comments only after variable/routine meaning is evidence-backed.
- Continue improving docs if new user memory or emulator traces provide
  stronger evidence:
  - variable map
  - routine map
  - data tables
  - unresolved questions

### Longer-Term Optional Work

- Extend automated verification beyond `tools/verify_yoshi_build.sh` if future
  recovery adds more generated artifacts or subsystem-specific checks.
- Build a higher-level architecture overview of the recovered source.
- Produce subsystem-level handoff notes for gameplay, link, sound, graphics,
  result records, and rendering.
- Compare uncertain behavior with user memory when static analysis leaves more
  than one plausible interpretation.

## Time Estimate

### Checkpoint Estimate

These estimates assume the same quality bar used so far: every source change is
validated byte-identical and committed as an evidence-backed chunk.

| Scope | Estimated Time | Result |
|-------|----------------|--------|
| Close one simple naming chunk | 10-30 minutes | One small set of existing raw references replaced and committed. |
| One evidence-backed WRAM structure | 30-90 minutes | Names, source replacements, memory-map/docs update, rebuild, commit. |
| One data/code boundary correction | 1-3 hours | Exact range split, labels, docs, byte-identical rebuild, commit. |
| Remaining checklist-oriented cleanup pass | Complete | The 541-item checklist is closed and synchronized with final verification. |
| Practical maintainable recovery | Complete for this pass | Readable, buildable, subsystem-documented source, still with explicit uncertainty notes where evidence is insufficient. |
| Original-source-equivalent recovery | Not bounded | Without the original source, exact symbol names, comments, and structure cannot be proven. |

### Estimate Rationale

- The user-observed session time is already about 6 hours for a set of small,
  carefully verified recovery chunks.
- Since the current checkpoint, the repository has 42 commits in this recovery
  session. That is good throughput, but many commits are intentionally narrow:
  each one preserves behavior and avoids speculative broad rewrites.
- Current scan shows 0 raw `$Cxxx` occurrences in `bank_000.asm` /
  `bank_001.asm`. Remaining low-confidence WRAM roles are represented by
  explicit symbolic constants and documented as evidence limits.
- The raw direct branch problem is currently solved, so remaining work is less
  about obvious `call $xxxx` labels and more about semantic recovery, which is
  slower.
- The generated `jr_000_*` local-label problem is now solved for Bank 0/1
  source, so the remaining work is no longer a mechanical local-label pass.
- Each accepted chunk includes fixed overhead:
  - read all references
  - inspect surrounding code
  - decide confidence and name
  - edit source with labels/constants
  - update docs
  - run `git diff --check`
  - run `make -B`
  - verify `cmp -s yoshi.gb game.gb`
  - verify SHA-256
  - confirm generated artifacts are unchanged
  - commit only the intended files
- Gameplay algorithm recovery is the slowest part. Variables can often be named
  locally, but proving board semantics, match rules, and result flow requires
  following multi-routine behavior across Bank 0 and Bank 1.
- “Perfect source” has no finite estimate because the original source is gone.
  The attainable target is a behavior-preserving, maintainable source with clear
  evidence and confidence levels.

## Operating Rules Going Forward

- Keep commits small and reversible.
- Preserve byte-identical output for every recovery chunk.
- Do not rename uncertain values as facts; document uncertainty explicitly.
- Prefer high-confidence structures over broad speculative comments.
- Leave unrelated/untracked user files such as `CLAUDE.md` untouched.
