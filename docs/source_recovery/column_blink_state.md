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
`DrawColumnSprite`.

## Result Rank State

`RESULT_RANK_POSITION` (`$C7AD`) stores the rank/high-score position returned by
`CalcRankPosition` inside `ProcessNewHighScore`.

The result path reads it in three places:

- `DrawScoreRanking` converts it into the two tile ranges drawn at rows `$0804`
  and `$0904`.
- The B-game round-end branch checks whether it is nonzero before resuming play
  through `StartNextRound`.
- `ProcessNewHighScore` writes the latest computed value for both 1P and 2P
  result paths.
