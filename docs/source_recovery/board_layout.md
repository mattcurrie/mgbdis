# Board Layout

This note tracks the first recovered structure of `BOARD_DATA` at `$C62A`.

## Storage Shape

| Constant | Value | Evidence |
|----------|-------|----------|
| `COLUMN_COUNT` | `$04` | `DrawAllColumns`, `SeedColumnTopRows`, and several column-state loops process four columns. |
| `BOARD_COLUMN_STRIDE` | `$10` | `MovePieceLeft` and `GetFallSpeed` select a column block by shifting `PIECE_ROTATION` left four times. |
| `BOARD_DATA_SIZE` | `$40` | `GenerateNextPiece` clears `$40` bytes starting at `BOARD_DATA`; this matches `COLUMN_COUNT * BOARD_COLUMN_STRIDE`. |
| `BOARD_CELL_STRIDE` | `$02` | `DrawAllColumns` advances the source pointer by two bytes for each visible row. `GetFallSpeed` also indexes by raw row offset after selecting a 16-byte column block. |
| `BOARD_VISIBLE_ROW_COUNT` | `$07` | `DrawAllColumns` draws seven visible entries per column. |
| `BOARD_FALL_END_ROW` | `$0F` | A-type setup seeds `COLUMN_TOP_ROWS` with this value, `ProcessInputTitle` returns immediately when the seed is already this value, B-type clear detection requires all four column rows to reach it, `UpdateMatchState` skips landing-progress handling at this row, and `UpdateFallTimer` stops scanning when `PIECE_FALL_POS` or the scan row reaches it. |
| `BOARD_SCAN_TRIGGER_PAYLOAD` | `$07` | `UpdateMatchState` calls `ScanBoard` only for this staged payload, and `ScanBoard` redraws this payload while animating the scan. |
| `BOARD_SCAN_TARGET_PAYLOAD` | `$08` | `GetFallSpeed` scans the selected column for this payload, and `UpdateLandingProgress` applies its unresolved landing-counter adjustment only for this staged payload. |
| `BOARD_SCAN_STEP_MAX` | `$07` | `ScanBoard` increments its local sound/animation step counter up to this value; the same counter selects scan sounds from `SND_BOARD_SCAN_STEP_BASE` down to `SND_BOARD_SCAN_STEP_MIN`. |
| `BOARD_SCAN_SEND_FRAMES` | `$07` | Each `ScanBoard` animation step calls `Send2PData` for this many inner frames. |

The board is currently best described as four 16-byte column blocks. Column
selection uses `PIECE_ROTATION * $10` in `MovePieceLeft` and `GetFallSpeed`;
row selection then adds the current row/fall position within that block.

`BOARD_FALL_END_ROW` is a row boundary for falling/scanning rather than a
confirmed piece value. A column with top-row state `$0F` is treated as clear by
the B-type completion check.

`DrawAllColumns` reads from `BOARD_DATA + 1`, draws seven entries per column,
advances by two bytes per row, then skips two bytes before the next column.
That supports the current "visible row cells are every two bytes" model, but
the exact meaning of the paired/interleaved bytes still needs more tracing.

## Main Consumers

- `GenerateNextPiece` clears the full `$40`-byte area.
- `DrawAllColumns` renders the visible board entries from the odd offsets.
- `GetFallSpeed` probes a column block for `BOARD_SCAN_TARGET_PAYLOAD` while
  scanning fall positions.
- `MovePieceLeft` writes the staged piece payload back near the selected
  column/row position.
- `CommitFallingPieceToBoard` updates a `COLUMN_TOP_ROWS` entry, clears the
  drawn falling position, and calls `UpdateBoard`.
