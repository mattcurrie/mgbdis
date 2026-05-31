# Source Recovery Optional Refinement Checklist

This checklist records optional refinement chunks after the completed 541-item
source-recovery pass. It is intentionally evidence-first: each source edit
should make the recovered source more maintainable without changing the ROM.
None of these notes are required remaining work for the completed checklist.

## Verification Habit

- Run `tools/verify_yoshi_build.sh` before every commit.
- Treat `Yoshi/yoshi.gb` as the preserved baseline.
- Keep `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb` unless there is an
  explicit, separately documented reason to change behavior.
- Commit only the intended source and documentation files for the chunk.
- Leave unrelated local files, including `CLAUDE.md`, untouched.

## Optional Refinement Chunks

### Board Cell And Piece Representation

- `BOARD_DATA` is now modeled as four 16-byte column blocks whose live visible
  payloads are the odd offsets. Keep the even byte under
  `BOARD_CELL_UNREAD_PAIR_OFFSET` until a real producer/consumer appears.
- Follow `BOARD_SCAN_TRIGGER_PAYLOAD` and `BOARD_SCAN_TARGET_PAYLOAD` from
  producer to visible piece effect before broadening comments.
- Keep `UNRESOLVED_LANDING_RESET_BYTE_0`,
  `UNRESOLVED_LANDING_RESET_BYTE_1`, `UNRESOLVED_LANDING_SCAN_COUNTER`, and
  `UNRESOLVED_LANDING_RESET_TIMER` under their unresolved names until there is
  independent read/write evidence beyond the current landing/scan context. The
  latest all-source and recent-history search found no hidden producer.
- Cross-check any proposed board-field name against `board_layout.md`,
  `column_state.md`, `drop_animation_state.md`, and `fall_timing.md`.

### Gameplay Routine Naming

- Name drop, rotation, match, clear, scoring, level, and game-over routines only
  when call sites and state changes agree.
- Prefer narrow names tied to proven behavior over broad game-design terms.
- Keep comments local and confidence-bounded when a routine has more than one
  plausible role.
- `HandlePlayfieldInput` now covers per-frame cursor/drop/fast-fall input; keep
  falling/landing names tied to `UpdateFallingPieceMotionAndLanding` and
  related board writes.
- `UpdateFallingPieceMotionAndLanding` now has constants for its active return,
  8-pixel fall sprite step, top-row game-over check, and column-top overflow
  sentinel; keep broader match/clear terminology tied to additional board-cell
  evidence.
- `GetLevelFallDelay` now covers only the `LevelFallDelayTable` lookup; avoid
  using it as a broad falling-process name.
- `InitPlayfieldBoardAndPieceState` now covers playfield board/piece setup
  rather than an input drop path; keep future setup names tied to their reset
  and seed side effects.
- `GetSelectedColumnTopRow`, `StagePiecePayloadInSelectedColumn`, and
  `ClearCurrentGameplaySpriteObjectRecord` now cover the selected-column
  row lookup, staged board payload write, and current gameplay object clear
  path. Do not broaden these into full piece movement names until the paired
  board-cell semantics are better proven.
- `FindBoardScanTargetRow` and `ReadBoardCellAtColumnRow` now cover the
  selected-column scan for `BOARD_SCAN_TARGET_PAYLOAD`; keep target payload
  semantics scan-specific until the piece code values are mapped.

### Sprite Object Slots

- Keep `+$01` as an unused/padding byte unless a consumer appears. Its observed
  template seed is now named `SPRITE_OBJECT_UNUSED_1_INIT_VALUE`.
- Keep `+$03` scoped to the BGM cursor toggled-frame shadow and `+$0F` scoped
  to the Down-held fast-fall clamp byte unless a second consumer appears.
- Slot 0's initializer is now `InitPlayerCursorObject`; keep future slot-0
  names tied to the player cursor evidence unless another producer is found.
- The playfield setup sprite clear helper is now `ClearSpriteObjectBuffer`;
  preserve the documented `$FF`-byte clear behavior if this is refined later.
- Keep object type `$07` scoped to `SPRITE_OBJECT_TYPE_RESERVED_7` until a
  producer is found. High-bit variants `$81-$87` are renderer-supported
  attribute aliases of `$01-$07`, but no current producer has been found; only
  revisit this if a setup table or writer starts producing high-bit type bytes.
- Update `sprite_oam.md` only when a field role is visible in both a producer
  and a consumer.

### Sound And Music

- Decode more sequence commands from actual stream examples before renaming
  medium-confidence `SOUND_CH_*` fields.
- The command-dispatch and pitch-slide helpers now use behavior names. Continue
  with command-specific handler names only where the operand parsing and state
  side effects are both clear.
- The first sound parser local cleanup now names sequence-end, `$FE`
  loop-target, `$D0-$DF` length/envelope, and `$E8/$EA/$EB` vibrato/pitch-slide
  branch points. Keep later command labels scoped to observed state writes
  rather than assigning final music-engine terminology too early.
- The parser cleanup also names `$EC/$ED/$EE/$EF/$FC/$F0` checks by their
  observed duty/tempo/output-mask/nested-sound/duty-rotate/master-volume
  writes. `$F1/$F8/$E0` and the first note/sweep/channel-3 nested-sound
  branches are now named. The note-length, tempo, rest, output-mask, length
  register, wave-copy, pitch-slide-step, utility, sound-index priority, and
  `StartSoundSequence` channel-entry locals are now named too. Continue with
  later sound initializers only where the selected channel and state-array
  side effects are both clear.
- `UpdateSoundChannels` / `TickSoundChannel` now replace the stale link-style
  labels for the VBlank sound channel scan. Continue refining local sound labels
  only where a flag bit or state array has a proven role.
- `HandleWaveUpdate` is separate from the selected wave-pattern copy in
  `ProcessNote`; keep its exact audible role unresolved until the code-byte
  pattern written through `rNR32` is better understood.
- Tie channel roles to command behavior, not only byte offsets.
- Keep sound call-site aliases only where the surrounding game state proves the
  effect role.

### Graphics And Data Boundaries

- Identify Bank 3 screen/tile roles from load destinations and visible usage.
- 2P result header, badge, outcome, and status tilemap origins are now named.
  `FIELD_OCCUPANCY_SCAN_TOP_LEFT` (`$C4C8`) is also named; continue with any
  future repeated layout offsets only where a screen-region role is clear.
- Title-screen frame/panel origins from `InitTitleUI` are now named; avoid
  reusing those title names for result-screen rectangles unless the source
  context is also title setup.
- Link field-occupancy scan/count display is now named; leave the remaining
  result/matching layout offsets alone until their screen roles are clear.
- The round-local link staging clear helper is now `ClearLinkRoundState`; avoid
  reusing egg-system names for routines that only reset link bytes.
- Matching/link result animation origins at `$C4ED/$C4CA/$C59B/$C543/$C571`
  are now named.
- The final raw WRAM references are now symbolic unresolved constants; future
  work should refine `UNRESOLVED_*`, `SCORE_PRESERVED_UNUSED_BYTE`, and
  `SCORE_UNUSED_TILE_BASE_*` names only after finding a stronger consumer. The
  observed `$30` seed is named `SCORE_UNUSED_TILE_BASE_INITIAL`, but the copied
  and swapped bytes still have no confirmed display consumer.
- The Bank 0 helper labels `WaitVBlankFrames`, `ShiftMatchingOamPairX`, and
  `FillBytesWithD` now describe their behavior. Continue auditing older
  drawing/result helper names before assigning broader UI semantics.
- `ReloadGameTilesAndRequestRedraw` and `WaitFramesSetTransitionOnInput` now
  replace the misleading `DrawDigit` / `WaitFrames` labels.
- Elapsed-timer helpers now use behavior names:
  `DrawRoundTimerDigits`, `ClearRoundTimerDigitsAndResume`, and
  `ClearTotalTimerDigitsAndResume`. `TickElapsedTimerDigits` also names the
  60-frame divider, decimal digit rollovers, seconds-tens limit, and 99:59
  clamp constants.
- Playfield HUD helpers now use behavior names:
  `DrawPlayfieldLevelDigits`, `DrawPlayfieldSpeedValue`,
  `DrawPlayfieldEggDisplay`, and `DrawEggTextFrame0`.
- Playfield HUD coordinate-selection locals now use behavior names and packed
  coordinate constants for the 2P, A-type, and B-type level/speed/egg display
  destinations. The nearby `UnusedDrawPlayfieldGameTypeHeader` fragment should
  remain marked unused unless a real entry path is found.
- Playfield timer/link header helpers now use behavior names:
  `DrawBTypeTimerHeaderAndDigits`, `DrawPlayfieldRoundTimerDigits`, and
  `DrawTwoPlayerPlayfieldRoleHeaders`.
- Playfield side-panel layout helpers now use behavior names:
  `Draw1PPlayfieldSidePanelLabelRow0`,
  `DrawPlayfieldSidePanelLabelRow1`,
  `DrawPlayfieldBottomColumnMarkers`, and the three
  `Blank*PlayfieldSidePanelRows` helpers.
- Coordinate-based tilemap helpers now use behavior names:
  `FillTilemapRectByCoord` and `DrawSequentialTileRowByCoord`.
- Result record setup frame/type/header/detail layout origins are now named;
  continue with remaining layout offsets only when their screen role is proven
  by surrounding setup and consumer code.
- A-type round-complete summary messages and reveal tables at `$3799-$37DF`
  are now data; nearby helpers are scoped to the reveal behavior as
  `RevealRoundComplete*Block` and `AddScoreAndAnimateManualOamPair`.
- The three A-type round-complete summary strings are now decoded as
  `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER`; the ROM0 tile source names
  now distinguish the summary/reveal graphics block from the text-tile block.
- Continue converting repeated table and text blocks from fake code into named
  data ranges.
- Preserve exact bytes and labels around any ambiguous code/data boundary until
  the verifier proves the split is behavior-preserving.

### User Memory Comparison

- Use developer memory to prioritize and confirm ambiguous behavior.
- Do not let memory override binary evidence when the code shows a different
  behavior.
- Record any confirmed historical fact separately from static code facts.

## Chunk Checklist

For each future chunk:

1. Inspect `git status --short --branch` and the relevant notes.
2. Read all references before editing.
3. Make one behavior-preserving symbolic, data-boundary, or documentation
   improvement.
4. Update the relevant source recovery notes and `task_plan.md` if the chunk
   changes plan status.
5. Run `tools/verify_yoshi_build.sh`.
6. Review `git diff --check` and staged files.
7. Commit only the intended files.
8. Leave the final status clean except for unrelated user-local files.
