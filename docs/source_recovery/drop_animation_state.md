# Drop Animation State

This note documents the recovered WRAM state used by `StartDropAnim` and
`AnimateDropping` after a down/drop input starts a column swap/drop cascade.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C75D` | `DROP_ANIM_ACTIVE` | `StartDropAnim` sets it to `$FF`, `AnimateDropping` returns immediately when it is zero, `CheckMatch` blocks a new drop while it is nonzero, and the cascade completion path clears it. |
| `$C75E` | `DROP_ANIM_FRAME_TIMER` | `AnimateDropping` decrements it each frame and reloads it with `DROP_ANIM_FRAME_PERIOD` before advancing the cascade states. |
| `$C761` | `DROP_ANIM_COLUMN` | `StartDropAnim` stores the selected column index here. Collision checks and `CalcGridPosition` reuse it while the cascade runs. |
| `$C762` | `DROP_ANIM_GRID_ROW_TMP` | `CalcGridPosition` writes `b * 2` here as scratch before using the same value in `H`; no independent consumer has been confirmed. |
| `$C764` | `DROP_ANIM_DOWN_STATES` | First seven-state cascade array processed by `AnimateDropDown`; entries are spaced two bytes apart. |
| `$C774` | `DROP_ANIM_UP_STATES` | Second seven-state cascade array processed by `AnimateDropUp`; entries are spaced two bytes apart. |

## Flow

- `CheckMatch` starts the sequence only when `DROP_ANIM_ACTIVE` is zero.
- `StartDropAnim` stores the selected column, seeds the first down/up cascade
  entries with state `1`, sets the frame timer to `1`, and marks the sequence
  active with `$FF`.
- `AnimateDropping` advances the two seven-entry cascade arrays every two
  frames. State `3` seeds the next entry two bytes later when more rows remain;
  state `5` clears the current entry.
- When the second cascade finishes its last entry, the routine swaps the two
  selected bytes in the `$C66A` column-state array and clears
  `DROP_ANIM_ACTIVE`.

The names are high confidence for `$C75D/$C75E/$C761/$C764/$C774`. `$C762` is
named only as local scratch because current evidence shows a write but no
separate read outside the immediate `CalcGridPosition` flow.
