# Piece Display State

This note records the four-byte piece display state array used by the
`DisplayResults` / `HandleGameOver` path.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$FF97-$FF9A` | `PIECE_DISPLAY_SLOT_ORDER` | `InitPieceDisplaySlotOrder` initializes four slot indices `0,1,2,3`; `ShufflePieceDisplaySlotOrder` swaps two randomly selected entries; `DisplayResults` uses this order array to choose which `PIECE_DISPLAY_STATES` slot receives each display code. |
| `$C673-$C677` | `PIECE_DISPLAY_CODE_POOL` | `InitPieceDisplayCodePool` fills five codes `1..5`; `ShufflePieceDisplayCodePool` swaps randomly selected entries; `DisplayResults` reads this pool by `display_count - 1` before calling `ProcessMenuSelection`. |
| `$C6A3-$C6A6` | `PIECE_DISPLAY_STATES` | `DisplayResults` clears four bytes, writes one state per selected slot, and `HandleGameOver` scans the same four bytes to emit sprite object type `$02` through `AnimateGameOver`. |

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
- `HandleGameOver` scans the four entries. Each nonzero value becomes the
  frame/tile payload passed to `AnimateGameOver`.
- `AnimateGameOver` writes sprite object type `$02` into slots 1-4, sets the
  frame from the state byte, sets base X from the array index, sets base Y to
  `$28`, and copies the state byte into the slot's `SPRITE_OBJECT_TILE_ID`.
- `CheckGameOver` and `TitleScreenLoop` can force one or more nonzero entries
  to `$07`, matching the special piece/display code used in the game-over path.

The name is intentionally generic. These bytes are not only a raw game-over
flag; they are the per-slot display state consumed by the piece sprite builder.
