# Piece Display State

This note records the four-byte piece display state array used by the
`DisplayResults` / `HandleGameOver` path.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$FF97-$FF9A` | `PIECE_DISPLAY_SLOT_ORDER` | `InitPieceDisplaySlotOrder` initializes four slot indices `0,1,2,3`; `ShufflePieceDisplaySlotOrder` swaps two randomly selected entries; `DisplayResults` uses this order array to choose which `PIECE_DISPLAY_STATES` slot receives each display code. |
| `$C673-$C677` | `PIECE_DISPLAY_CODE_POOL` | `InitPieceDisplayCodePool` fills five codes `1..5`; `ShufflePieceDisplayCodePool` swaps randomly selected entries; `DisplayResults` reads this pool by `display_count - 1` before calling `ProcessMenuSelection`. |
| `$C697` | `PIECE_DISPLAY_REMAINING` | `ProcessMenuLoop` stores the same table byte as `PIECE_DISPLAY_COUNT`; `MovePieceLeft` and `ShowResults` decrement it, but no independent read has been confirmed. |
| `$C698` | `PIECE_DISPLAY_COUNT` | `ProcessMenuLoop` loads this from the second byte of the current `GameTurnParamTable` row, and gameplay setup forces it to `2`; `DisplayLevel`, `UpdateMenuCursor`, and `HandleDrop` pass it back into `DisplayResults`. |
| `$C6A3-$C6A6` | `PIECE_DISPLAY_STATES` | `DisplayResults` clears four bytes, writes one state per selected slot, and `HandleGameOver` scans the same four bytes to emit sprite object type `$02` through `AnimateGameOver`. |
| `$C6AD` | `PIECE_DISPLAY_FORCE_ALL_STATES_FLAG` | Set by one `ProcessMenuSelection` path that returns `PIECE_DISPLAY_FORCED_STATE`; `ApplyAllForcedPieceDisplayStates` tests it and rewrites every nonzero entry in `PIECE_DISPLAY_STATES` to that forced state. `DisplayResults` clears the flag after applying it. |
| `$C6AF` | `PIECE_DISPLAY_BLINK_TIMER` | `GameMainUpdate` calls `UpdatePieceDisplayBlink` every frame. When this timer reaches zero, the routine reloads `$20`, scans sprite object slots 1-8, and toggles bit `$10` in the frame byte for active object type `$02`, except frames `$07` and `$08`. |
| `$C6F7` | `PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG` | Set by another timer-gated `ProcessMenuSelection` path; `ApplyFirstForcedPieceDisplayState` consumes it and rewrites only the first nonzero `PIECE_DISPLAY_STATES` entry to `PIECE_DISPLAY_FORCED_STATE`. |
| `$C6F8` | `PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG` | `DisplayResults` sets this one-shot flag when the requested display count is at least three. The next `ProcessMenuSelection` call clears it and skips the B-type timer-gated special-selection branch. |

## Flow

- `DisplayResults` stores the selected display state in `SCREEN_STATE`, clears
  `PIECE_DISPLAY_STATES`, then fills entries selected through the `$FF97`
  slot-order scratch array, now named `PIECE_DISPLAY_SLOT_ORDER`.
- The values written into `PIECE_DISPLAY_STATES` come from
  `ProcessMenuSelection`, after indexing `PIECE_DISPLAY_CODE_POOL`.
  `ProcessMenuSelection` returns piece/display codes such as `$01`, `$02`,
  `$03`, `$04`, `$07`, and `$08`.
- `GameMainUpdate` calls `ShufflePieceDisplaySlotOrder` and
  `ShufflePieceDisplayCodePool` once per frame. Both helpers choose entries
  with `MultiplyAndCount` masked by `$38`, so the selected index range is
  currently `0..3`.
- During initial board fill, `ProcessInputTitle` shuffles
  `PIECE_DISPLAY_CODE_POOL` three times, then uses pool entry `+3` as the next
  generated piece/display code before rotating it away from an adjacent match.
- `PIECE_DISPLAY_REMAINING` receives the same table byte as `PIECE_DISPLAY_COUNT`
  and is decremented by piece commit/result paths. No independent read has been
  confirmed yet, so the exact gameplay effect remains open.
- `HandleGameOver` scans the four entries. Each nonzero value becomes the
  frame/tile payload passed to `AnimateGameOver`.
- `AnimateGameOver` writes sprite object type `$02` into slots 1-4, sets the
  frame from the state byte, sets base X from the array index, sets base Y to
  `$28`, and copies the state byte into the slot's `SPRITE_OBJECT_TILE_ID`.
- `GameOverSequence` scans the same state array in reverse and writes sprite
  object type `$02` into slots 5-8. It uses the state byte as the frame and
  derives base X from the reverse display index.
- `PIECE_DISPLAY_BLINK_TIMER` drives the visible display-piece blink by toggling
  bit `$10` in the sprite frame field for active type `$02` objects. Frames
  `$07` and `$08` are left unchanged.
- `ApplyFirstForcedPieceDisplayState` and `ApplyAllForcedPieceDisplayStates` can
  force one or more nonzero entries to `PIECE_DISPLAY_FORCED_STATE` (`$07`).
  The flags are written by timer-gated branches in `ProcessMenuSelection`.

The name is intentionally generic. These bytes are not only a raw game-over
flag; they are the per-slot display state consumed by the piece sprite builder.
