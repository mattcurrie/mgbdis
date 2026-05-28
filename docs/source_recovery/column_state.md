# Column State

This note tracks the first recovered gameplay column state around `$C66A`.

## Column Top Rows

`COLUMN_TOP_ROWS` (`$C66A-$C66D`) is a four-byte array, one byte per gameplay
column.

Evidence:

- `SeedColumnTopRows` seeds all four entries from `COLUMN_TOP_ROW_SEED`
  (`$C699`), which is loaded from `LevelCountTable` in the B-game setup path or
  forced to `$0F` in the A-game path.
- `MovePieceUp` indexes the array by `PIECE_ROTATION` and returns the selected
  column's current row/fall target.
- `DrawColumnSprite` indexes the same array while drawing the column blink
  sprite, subtracting three rows from the stored value before drawing.
- `AnimateDropping` swaps two adjacent `COLUMN_TOP_ROWS` entries after the drop
  cascade finishes, matching the selected-column swap behavior.
- The B-game completion check scans all four entries and finishes when they all
  reach `$0F`.

The exact board coordinate convention still needs more work, so the current
name intentionally says "top rows" rather than "height" or "empty row".

## Drop Cursor Animation

`DROP_CURSOR_ANIM_ACTIVE` (`$C66F`) and `DROP_CURSOR_FRAME_TIMER` (`$C670`) drive
the short slot-0 cursor frame animation after a drop input starts.

Evidence:

- `CheckMatch` sets `DROP_CURSOR_ANIM_ACTIVE` when it accepts an A/B drop input.
- `InitGameState2` decrements `DROP_CURSOR_FRAME_TIMER`, reloads it with `2`,
  advances `SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_FRAME`, and clears the active
  flag when the frame reaches `0` or `4`.
- `DisplayScore` keeps its update timer active while either
  `DROP_CURSOR_ANIM_ACTIVE` or `DROP_ANIM_ACTIVE` is nonzero.
- The slot-0 cursor uses X positions separated by `$20`; right/left input also
  increments/decrements `FIELD_COLUMN_TILE_PATTERN_INDEX`, which selects the
  16-byte `FieldColumnTilePatternTable` record copied by `LoadGameBGTiles`.

The adjacent `$C66E` byte is `SPRITE_OBJECT_DELAY_RELOAD`, documented with the
sprite object producer state in `sprite_oam.md`.
