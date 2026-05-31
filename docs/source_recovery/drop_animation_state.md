# Drop Animation State

This note documents the recovered WRAM state used by
`StartDropColumnSwapAnimation` and `AnimateDropping` after a drop input starts a
column swap/drop cascade.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C75D` | `DROP_ANIM_ACTIVE` | `StartDropColumnSwapAnimation` sets it to `$FF`, `AnimateDropping` returns immediately when it is zero, `HandlePlayfieldInput` blocks a new drop while it is nonzero, and the cascade completion path clears it. |
| `$C75E` | `DROP_ANIM_FRAME_TIMER` | `AnimateDropping` decrements it each frame and reloads it with `DROP_ANIM_FRAME_PERIOD` before advancing the cascade states. |
| `$C761` | `DROP_ANIM_COLUMN` | `StartDropColumnSwapAnimation` stores the selected column index here. Collision checks and `CalcGridPosition` reuse it while the cascade runs. |
| `$C762` | `DROP_ANIM_UNUSED_GRID_ROW_TMP` | `CalcGridPosition` writes `b * 2` here, then uses the same value directly from `H`; no direct read from this WRAM byte has been confirmed. |
| `$C764` | `DROP_ANIM_DOWN_STATES` | First seven-state cascade array processed by `AnimateDropDown`; entries are spaced two bytes apart. |
| `$C774` | `DROP_ANIM_UP_STATES` | Second seven-state cascade array processed by `AnimateDropUp`; entries are spaced two bytes apart. |

## Flow

- `HandlePlayfieldInput` starts the sequence only when `DROP_ANIM_ACTIVE` is zero.
- `StartDropColumnSwapAnimation` stores the selected column, seeds the first
  down/up cascade entries with `DROP_ANIM_STATE_START`, sets the frame timer to
  the same initial value, and marks the sequence active with
  `DROP_ANIM_ACTIVE_VALUE`. It returns `DROP_ANIM_ACCEPTED_RETURN_VALUE` in
  `A` after accepting a new sequence, but the current caller immediately
  continues without reading that value.
- `AnimateDropping` advances the two seven-entry cascade arrays every two
  frames. It starts from `BOARD_COLUMN_BOTTOM_VISIBLE_CELL`, applies the
  selected column's 16-byte board stride, and then steps upward by two bytes
  per cascade entry. `DROP_ANIM_STATE_TRIGGER_NEXT` seeds the next entry two
  bytes later when more rows remain; `DROP_ANIM_STATE_END` clears the current
  entry back to `DROP_ANIM_STATE_INACTIVE`.
- The cascade loops now use `BOARD_CELL_STRIDE` for board-cell pointer
  movement and `DROP_ANIM_STATE_STRIDE` for the two-byte state-array spacing.
- The down and up passes are now labeled as
  `AnimateDropDownCascadeLoop` / `AdvanceDropDownCascadeSlot` and
  `AnimateDropUpCascadeLoop` / `AdvanceDropUpCascadeSlot`.
- The per-entry state handlers inside `AnimateDropDown` and `AnimateDropUp`
  are also labeled by branch role. The down path uses
  `CheckDropDownState2`, `CheckDropDownState3`,
  `HandleDropDownFinalState`, and the matching `RedrawDropDown*` return
  labels. The up path mirrors that with `CheckDropUpState2`,
  `CheckDropUpState3`, `HandleDropUpState3Boundary`,
  `HandleDropUpFinalState`, and `DrawDropUp*Piece`.
- Redraw paths clear the side column for `GRID_PIECE_TILE_ROWS` rows with
  `GRID_COLUMN_CLEAR_TILE`, matching the 4x2 visible footprint used by
  `DrawGridPiece`.
- The late drop-up boundary handlers compare the saved row delta against
  `DROP_ANIM_UP_CLEAR_LEFT_MIN_DELTA` before clearing the left side column;
  smaller/carrying deltas draw the piece without that side-column clear.
- `ClearDropAnimationStateLoop` clears the `$47`-byte animation/state span
  starting at `DROP_ANIM_ACTIVE`. `ReturnFromStartDropColumnSwapAnimation`
  preserves the caller's `BC` whether a new drop sequence was accepted or
  ignored because one is already active.
- When the second cascade finishes its last entry, the routine swaps the two
  selected bytes in the `COLUMN_TOP_ROWS` column-state array and clears
  `DROP_ANIM_ACTIVE`. The completion path is now named
  `FinishDropCascadeAndSwapColumns`; it swaps the visible column cells through
  `SwapDropAnimationColumnCellsLoop` using `BOARD_CELL_STRIDE`, and then swaps
  the top-row bytes at `SwapColumnTopRowsAfterDrop`.
- `CheckDropCollisionAgainstActiveObjects` scans active gameplay sprite slots through
  `ScanDropCollisionSpriteSlotsLoop`, skipping inactive slots at
  `SkipInactiveDropCollisionSlot` and returning carry via
  `ReturnDropCollisionDetected` when the candidate drop column overlaps an
  existing active object. The collision path compares the row delta against
  `DROP_COLLISION_Y_OVERLAP_LIMIT`, shifts the object's base X by
  `DROP_COLLISION_SPRITE_X_STEP`, and then marks
  `SPRITE_OBJECT_GRID_COLUMN` as `SPRITE_OBJECT_GRID_COLUMN_UNSET` so
  `UpdateDropPositions` derives the new grid column from base X.
- `ClearDropAnimationState` clears `DROP_ANIM_CLEAR_SIZE` bytes from
  `DROP_ANIM_ACTIVE`; this reaches the byte before
  `COLUMN_BLINK_GLOBAL_TIMER`.

The names are high confidence for `$C75D/$C75E/$C761/$C764/$C774`. `$C762` is
kept as an unused/write-only scratch because current evidence shows a write but
no separate read outside the immediate `CalcGridPosition` register flow.
