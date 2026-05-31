# Column Blink And Result Rank State

This note documents the recovered state bytes at `$C7A4-$C7AD`.

## Column Blink State

| Address | Name | Evidence |
|---------|------|----------|
| `$C7A4` | `COLUMN_BLINK_GLOBAL_TIMER` | `UpdateColumnBlinkState` increments this byte and wraps it at `COLUMN_BLINK_GLOBAL_PERIOD` (`$30`). |
| `$C7A5-$C7A8` | `COLUMN_BLINK_SLOT_TIMERS` | Four per-slot counters paired with `COLUMN_BLINK_SLOT_FLAGS`; a nonzero slot timer increments until `COLUMN_BLINK_SLOT_PERIOD` (`$10`). |
| `$C7A9-$C7AC` | `COLUMN_BLINK_SLOT_FLAGS` | Four active/frame bytes. `InitBlinkState` sets them to `1`; title init clears them. `UpdateColumnBlinkState` toggles each active flag between `1` and `2`, then passes the value to `DrawColumnSprite`. |

`UpdateColumnBlinkState` iterates four slots by walking `COLUMN_BLINK_SLOT_FLAGS`
and `COLUMN_BLINK_SLOT_TIMERS` in parallel. Slots with flag `0` are skipped.
Active slots toggle between the two sprite frames and redraw through
`DrawColumnSprite`, whose local row labels are named `DrawColumnSpriteRow0..2`.
`DrawColumnSprite` uses `COLUMN_SPRITE_FRAME_BLOCK_SIZE` to switch between the
two column-sprite frame blocks inside `ColumnSpritePatternTable`: frame value
`COLUMN_BLINK_FRAME_2` uses `ColumnSpritePatternFrame2Block`, while frame value
`COLUMN_BLINK_FRAME_1` adds the `$30`-byte block size and uses
`ColumnSpritePatternFrame1Block`.
`UnreachedColumnSpritePatternTailRows` sits immediately after the two live frame
blocks and is not selected by this live four-slot/two-frame path.
The internal loop is now labeled as `BeginColumnBlinkSlotScan`,
`ColumnBlinkSlotLoop`, `TickColumnBlinkSlotTimer`,
`ToggleColumnBlinkSlotFrame`, `DrawColumnBlinkSlot`, and
`AdvanceColumnBlinkSlot`.

## Result Rank State

`RESULT_RANK_POSITION` (`$C7AD`) stores the rank/high-score position returned by
`ResolveResultRankPosition` inside `ProcessRoundResultAndEnterRoundEnd`.

The result path reads it in three places:

- `DrawScoreRanking` converts it into the two tile ranges drawn at
  `RESULT_RANK_TOP_COORD` and `RESULT_RANK_BOTTOM_COORD`, each
  `RESULT_RANK_TILE_RUN_LENGTH` tiles wide. `NormalizeRankTopTileIndex` and
  `NormalizeRankBottomTileIndex` handle `RESULT_RANK_SPECIAL_POSITION_CODE`
  by drawing `RESULT_RANK_FIRST_PLACE` instead of using the raw swapped
  position byte.
- The B-game round-end branch checks whether it is nonzero before resuming play
  through `StartNextRound`.
- `ProcessRoundResultAndEnterRoundEnd` writes the latest computed value for both 1P and 2P
  result paths.
