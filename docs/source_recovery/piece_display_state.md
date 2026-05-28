# Piece Display State

This note records the four-byte piece display state array used by the
`DisplayResults` / `HandleGameOver` path.

## Variables

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C6A3-$C6A6` | `PIECE_DISPLAY_STATES` | `DisplayResults` clears four bytes, writes one state per selected slot, and `HandleGameOver` scans the same four bytes to emit sprite object type `$02` through `AnimateGameOver`. |

## Flow

- `DisplayResults` stores the selected display state in `SCREEN_STATE`, clears
  `PIECE_DISPLAY_STATES`, then fills entries selected through the `$FF97`
  slot-order scratch array.
- The values written into `PIECE_DISPLAY_STATES` come from
  `ProcessMenuSelection`, which returns piece/display codes such as `$01`,
  `$02`, `$03`, `$04`, `$07`, and `$08`.
- `HandleGameOver` scans the four entries. Each nonzero value becomes the
  frame/tile payload passed to `AnimateGameOver`.
- `AnimateGameOver` writes sprite object type `$02` into slots 1-4, sets the
  frame from the state byte, sets base X from the array index, sets base Y to
  `$28`, and copies the state byte into the slot's `SPRITE_OBJECT_TILE_ID`.
- `CheckGameOver` and `TitleScreenLoop` can force one or more nonzero entries
  to `$07`, matching the special piece/display code used in the game-over path.

The name is intentionally generic. These bytes are not only a raw game-over
flag; they are the per-slot display state consumed by the piece sprite builder.
