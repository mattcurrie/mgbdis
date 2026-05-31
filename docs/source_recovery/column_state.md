# Column State

This note tracks the first recovered gameplay column state around `$C66A`.

## Column Top Rows

`COLUMN_TOP_ROWS` (`$C66A-$C66D`) is a four-byte array, one byte per gameplay
column.

Evidence:

- `SeedColumnTopRows` seeds all four entries from `COLUMN_TOP_ROW_SEED`
  (`$C699`), which is loaded from `BTypeColumnTopRowSeedTable` in the B-game
  setup path or forced to `BOARD_FALL_END_ROW` (`$0F`) in the A-game path.
  The B-game table entries are now expressed with
  `B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_0..4`.
- `GetSelectedColumnTopRow` indexes the array by
  `FALLING_PIECE_GRID_COLUMN`, the staged object's grid-column field, leaves
  `HL` pointing at the selected entry, and returns the selected column's
  current row/fall target.
- `DrawColumnSprite` indexes the same array through
  `ReadColumnTopRowForSprite` while drawing the column blink sprite,
  subtracting three rows from the stored value before drawing up to three rows
  through `DrawColumnSpriteRow0..2`. The column sprite tile rows come from
  `ColumnSpritePatternTable` records selected by
  `GetColumnSpritePatternOffset`.
- `AnimateDropping` swaps two adjacent `COLUMN_TOP_ROWS` entries at
  `SwapColumnTopRowsAfterDrop` after the drop cascade finishes, matching the
  selected-column swap behavior.
- The B-game completion check scans all four entries and finishes when they all
  reach `BOARD_FALL_END_ROW`.

The exact board coordinate convention still needs more work, so the current
name intentionally says "top rows" rather than "height" or "empty row".

## Drop Cursor Animation

`DROP_CURSOR_ANIM_ACTIVE` (`$C66F`) and `DROP_CURSOR_FRAME_TIMER` (`$C670`) drive
the short slot-0 cursor frame animation after a drop input starts.

Evidence:

- `HandlePlayfieldInput` stores `DROP_CURSOR_ANIM_ACTIVE_VALUE` in
  `DROP_CURSOR_ANIM_ACTIVE` when it accepts an A/B drop input.
- `InitDropCursorAnimationState` initializes `DROP_CURSOR_ANIM_ACTIVE` to
  `DROP_CURSOR_ANIM_INACTIVE` before seeding `DROP_CURSOR_FRAME_TIMER`.
- `UpdateDropCursorAnimation` decrements `DROP_CURSOR_FRAME_TIMER`, reloads it with `2`,
  advances `SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_FRAME`, and clears the active
  flag when the frame reaches `0` or `4`.
- Its internal branches now name the two frame ranges:
  `AdvanceDropCursorAltFrame` handles frames at or above
  `DROP_CURSOR_FRAME_ALT_START` (`$04`), `StoreAdvancedDropCursorFrame` writes
  the advanced slot-0 frame, and `StopDropCursorFrameAnimation` clears
  `DROP_CURSOR_ANIM_ACTIVE` when the sequence reaches frame `$00` or `$04`.
- `UpdatePieceFallTimer` keeps its update timer active with
  `PIECE_FALL_TIMER_ANIM_HOLD_RELOAD` while either `DROP_CURSOR_ANIM_ACTIVE` or
  `DROP_ANIM_ACTIVE` is nonzero.
- The slot-0 cursor uses X positions separated by `$20`; right/left input also
  increments/decrements `FIELD_COLUMN_TILE_PATTERN_INDEX`, which selects the
  16-byte `FieldColumnTilePatternTable` record copied by `DrawFieldColumnTilePattern`.
  `InitPlayerCursorObject` seeds the index with
  `FIELD_COLUMN_TILE_PATTERN_INITIAL_INDEX`. The table has
  `FIELD_COLUMN_TILE_PATTERN_RECORD_COUNT` records, and `DrawFieldColumnTilePattern`
  copies one `FIELD_COLUMN_TILE_PATTERN_RECORD_SIZE` record to
  `FIELD_COLUMN_TILE_PATTERN_DEST_COORD`.
  The source now emits the table with `FIELD_COLUMN_TILE_PATTERN_ROW` rows,
  using `BLANK`, `LEFT_MARKER`, and `RIGHT_MARKER` roles for the blank and
  bottom-column marker tiles.

The adjacent `$C66E` byte is `SPRITE_OBJECT_DELAY_RELOAD`, documented with the
sprite object producer state in `sprite_oam.md`.
