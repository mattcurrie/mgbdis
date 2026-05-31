# Piece Display State

This note records the four-byte piece display state array used by the
`BuildPieceDisplayStatesForCount` / `BuildPieceDisplayObjects` path.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$FF97-$FF9A` | `PIECE_DISPLAY_SLOT_ORDER` | `InitPieceDisplaySlotOrder` initializes four slot indices with `PIECE_DISPLAY_SLOT_INDEX_0..3`; `ShufflePieceDisplaySlotOrder` swaps two randomly selected entries; `BuildPieceDisplayStatesForCount` uses this order array to choose which `PIECE_DISPLAY_STATES` slot receives each display code. |
| `$C673-$C677` | `PIECE_DISPLAY_CODE_POOL` | `InitPieceDisplayCodePool` fills five codes starting at `PIECE_DISPLAY_CODE_FIRST` / `PIECE_DISPLAY_CODE_1`; `ShufflePieceDisplayCodePool` swaps entries selected through `PIECE_DISPLAY_SHUFFLE_INDEX_MASK`, which currently limits the shuffled range to indices `0..3`; `BuildPieceDisplayStatesForCount` reads this pool by `display_count - 1` before calling `SelectPieceDisplayCode`. |
| `$C697` | `PIECE_DISPLAY_REMAINING` | `LoadGameTurnPieceDisplayStep` stores the same table byte as `PIECE_DISPLAY_COUNT`; `StagePiecePayloadInSelectedColumn` and `DecrementPieceDisplayRemaining` decrement it, but no independent read has been confirmed. |
| `$C698` | `PIECE_DISPLAY_COUNT` | `LoadGameTurnPieceDisplayStep` loads this from `GAME_TURN_PARAM_DISPLAY_COUNT_OFFSET`, the second byte of the current `GameTurnParamTable` row, and gameplay setup forces it to `2`; `UpdatePieceDisplayByGameType` routes A-type through `UpdateGameTurnPieceDisplay` and B-type through `RunBTypePieceDisplayUpdate`, both passing the count back into `BuildPieceDisplayStatesForCount`. |
| `$C6A3-$C6A6` | `PIECE_DISPLAY_STATES` | `BuildPieceDisplayStatesForCount` clears four bytes to `PIECE_DISPLAY_STATE_EMPTY`, writes one state per selected slot, and `BuildPieceDisplayObjectSlotsLoop` scans the same four bytes to emit `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` objects through `InitActivePieceDisplayObject`. |
| `$C6AD` | `PIECE_DISPLAY_FORCE_ALL_STATES_FLAG` | Set to `PIECE_DISPLAY_FORCE_FLAG_ACTIVE` by one `SelectPieceDisplayCode` path that returns `PIECE_DISPLAY_FORCED_STATE`; `ApplyAllForcedPieceDisplayStatesLoop` rewrites every nonzero entry in `PIECE_DISPLAY_STATES` to that forced state. `BuildPieceDisplayStatesForCount` clears the flag to `PIECE_DISPLAY_FORCE_FLAG_INACTIVE` after applying it. |
| `$C6AF` | `PIECE_DISPLAY_BLINK_TIMER` | `RunGameplayFrame` calls `UpdatePieceDisplayBlink` every frame. When this timer reaches zero, the routine reloads `PIECE_DISPLAY_BLINK_PERIOD`, scans `PIECE_DISPLAY_BLINK_SLOT_COUNT` sprite object slots through `ScanPieceDisplayBlinkSlotsLoop`, and toggles `PIECE_DISPLAY_BLINK_FRAME_TOGGLE_MASK` in the frame byte for active `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` objects, except `PIECE_DISPLAY_FORCED_STATE` and `PIECE_DISPLAY_BLINK_EXEMPT_STATE`. |
| `$C6F7` | `PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG` | Set to `PIECE_DISPLAY_FORCE_FLAG_ACTIVE` by another timer-gated `SelectPieceDisplayCode` path; `FindFirstForcedPieceDisplayStateLoop` scans for the first nonzero state before `StoreFirstForcedPieceDisplayState` rewrites it to `PIECE_DISPLAY_FORCED_STATE`. |
| `$C6F8` | `PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG` | `BuildPieceDisplayStatesForCount` sets this one-shot flag to `PIECE_DISPLAY_SKIP_SPECIAL_ACTIVE` when the requested display count reaches `PIECE_DISPLAY_SKIP_SPECIAL_MIN_COUNT` or more. The next `SelectPieceDisplayCode` call clears it and skips the B-type timer-gated special-selection branch. |

## Flow

- `BuildPieceDisplayStatesForCount` stores the requested display count in `SCREEN_STATE`; for
  display counts of `PIECE_DISPLAY_SKIP_SPECIAL_MIN_COUNT` or more, it sets
  `PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG` to
  `PIECE_DISPLAY_SKIP_SPECIAL_ACTIVE` before
  `InitPieceDisplayStateBuild`.
- `ClearPieceDisplayStatesLoop` clears `PIECE_DISPLAY_STATES`, then
  `BuildPieceDisplayStatesLoop` fills entries selected through the `$FF97`
  slot-order scratch array, now named `PIECE_DISPLAY_SLOT_ORDER`.
  `InitPieceDisplaySlotOrder` seeds that array with
  `PIECE_DISPLAY_SLOT_INDEX_0..3`.
- The values written into `PIECE_DISPLAY_STATES` come from
  `SelectPieceDisplayCode`, after indexing `PIECE_DISPLAY_CODE_POOL`.
  `SelectPieceDisplayCode` returns piece/display codes such as `$01`, `$02`,
  `$03`, `$04`, `$07`, and `$08`.
- `SelectPieceDisplayCode` has a default random path
  (`UseDefaultPieceDisplayCode`) and a B-type timer-gated path
  (`CheckBTypeTimedSpecialPieceDisplayCode` / `UseBTypeTimedSpecialPieceDisplayCode`).
  The timer-gated path can set `PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG` or
  `PIECE_DISPLAY_FORCE_ALL_STATES_FLAG` before returning
  `PIECE_DISPLAY_FORCED_STATE`.
- The timer-gated path is enabled only after
  `PIECE_DISPLAY_TIMED_SPECIAL_SECOND_DIGIT_MIN` and below
  `PIECE_DISPLAY_TIMED_SPECIAL_OCCUPANCY_LIMIT`. The named
  `PIECE_DISPLAY_*_RANDOM_*_THRESHOLD` constants are branch thresholds over the
  byte returned by `Multiply`; they describe return-code boundaries, not
  measured probabilities.
- `InitPieceDisplayCodePoolLoop` initializes the five-byte code pool with
  values starting at `PIECE_DISPLAY_CODE_FIRST` (`PIECE_DISPLAY_CODE_1`, `$01`) before the per-frame
  and initial-fill shuffles mutate it.
- `RunGameplayFrame` calls `ShufflePieceDisplaySlotOrder` and
  `ShufflePieceDisplayCodePool` once per frame. Both helpers choose entries
  with `MultiplyAndCount` masked by `PIECE_DISPLAY_SHUFFLE_INDEX_MASK`
  (`$38`); its `CountMaskedMultiplyBitsLoop` counts set bits after the mask,
  so the selected index range is currently `0..3`.
- During initial board fill, `FillInitialBoardCellLoop` shuffles
  `PIECE_DISPLAY_CODE_POOL` three times, then uses
  `INITIAL_BOARD_PIECE_POOL_OFFSET` (`+3`) as the next generated
  piece/display code before adjusting it away from an adjacent match.
- `AvoidInitialBoardAdjacentDuplicate` checks the board cell two bytes ahead of the target write
  position. If the generated code already matches that adjacent cell, it
  increments the code; if that increment reaches
  `INITIAL_BOARD_PIECE_WRAP_SENTINEL` (`$05`), it wraps back to
  `INITIAL_BOARD_PIECE_WRAP_CODE` (`$01`). This is an adjacency-avoidance rule
  for the initial board fill, not a general modulo operation for all display
  codes.
- `PIECE_DISPLAY_REMAINING` receives the same table byte as `PIECE_DISPLAY_COUNT`
  and is decremented by piece commit/result paths. No independent read has been
  confirmed yet, so the exact gameplay effect remains open.
- `GameTurnParamTable` has `GAME_TURN_PARAM_RECORD_COUNT` four-byte records.
  The fourth byte is always `GAME_TURN_PARAM_UNREAD_TAIL_VALUE` (`$01`), but no
  code path has been confirmed to read `GAME_TURN_PARAM_UNREAD_TAIL_OFFSET`.
  The source now uses `GAME_TURN_PARAM` for all complete records, leaving the
  `00:$0C40` continuation label exact with `GAME_TURN_PARAM_SPLIT_HEAD` /
  `GAME_TURN_PARAM_SPLIT_TAIL` around the record that crosses it.
- In B-type gameplay, `RunBTypePieceDisplayUpdate` refreshes menu/display
  state by calling `ClearPieceDisplayObjectSlots`, `UpdateFallAcceleration`,
  `BuildPieceDisplayObjects`, and `BuildPieceDisplayStatesForCount` with the current
  `PIECE_DISPLAY_COUNT`.
- `BuildPieceDisplayObjectSlotsLoop` scans the four entries. Each nonzero value
  becomes the frame/tile payload passed to `InitActivePieceDisplayObject`.
- `AddNonForcedPieceDisplayObjectsToUiScratch` scans the active display object
  slots by `SPRITE_OBJECT_SLOT_SIZE` and calls `AddPieceDisplayObjectToUiScratch`
  for each nonzero object.
  The helper reads the staged object tile/state byte and treats
  `PIECE_DISPLAY_FORCED_STATE` as the special case that does not increment its
  local count before accumulating into `UI_SCRATCH`.
- `InitActivePieceDisplayObject` writes `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` into slots 1-4, sets the
  frame from the state byte, clears base Y, sets grid column and base X from
  the array index, loads `SPRITE_OBJECT_DELAY_COUNTER` with
  `PIECE_DISPLAY_OBJECT_INITIAL_DELAY` (`$28`), sets the phase to
  `SPRITE_OBJECT_PHASE_WAIT`, and copies the state byte into
  `SPRITE_OBJECT_TILE_ID`.
- `BuildGameOverPieceDisplayObjectSlotsLoop` scans the same state array in
  reverse and writes `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` into slots 5-8. It uses
  the state byte as the frame and derives base X from the reverse display index;
  empty states advance through `AdvanceGameOverPieceDisplaySlot`. The
  `GAME_OVER_PIECE_DISPLAY_SLOT_OFFSET` maps state slots 1-4 onto object slots
  5-8.
- `ClearPieceSpriteObjectSlots` clears the full slot 1-8 span before playfield
  piece/display setup, using `PIECE_SPRITE_OBJECT_CLEAR_BYTES`.
- `ClearPieceDisplayObjectSlotsLoop` clears the producer-visible type/frame
  bytes for slots 5-8 and advances by
  `PIECE_DISPLAY_OBJECT_CLEAR_SLOT_ADVANCE` after the frame byte.
- `PIECE_DISPLAY_BLINK_TIMER` drives the visible display-piece blink by
  toggling `PIECE_DISPLAY_BLINK_FRAME_TOGGLE_MASK` (`$10`) in the sprite frame
  field for active `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` objects.
  `AdvancePieceDisplayBlinkSlot` walks `PIECE_DISPLAY_BLINK_SLOT_COUNT`
  candidate slots, while `ReturnFromTogglePieceDisplayFrame` leaves
  `PIECE_DISPLAY_FORCED_STATE` (`$07`) and
  `PIECE_DISPLAY_BLINK_EXEMPT_STATE` (`$08`) unchanged.
- `ApplyFirstForcedPieceDisplayState` and `ApplyAllForcedPieceDisplayStates` can
  force one or more nonzero entries to `PIECE_DISPLAY_FORCED_STATE` (`$07`).
  The all-state helper walks entries through
  `ApplyAllForcedPieceDisplayStatesLoop` and skips zero states at
  `AdvanceAllForcedPieceDisplayState`. The flags are written by timer-gated
  branches in `SelectPieceDisplayCode`.

The name is intentionally generic. These bytes are not only a raw game-over
flag; they are the per-slot display state consumed by the piece sprite builder.
