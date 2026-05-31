# Board Layout

This note tracks the first recovered structure of `BOARD_DATA` at `$C62A`.

## Storage Shape

| Constant | Value | Evidence |
|----------|-------|----------|
| `COLUMN_COUNT` | `$04` | `DrawAllColumns`, `SeedColumnTopRowsLoop`, and several column-state loops process four columns. |
| `BOARD_COLUMN_STRIDE` | `$10` | `StagePiecePayloadInSelectedColumn` and `ReadBoardCellAtColumnRow` select a column block by shifting the column index left four times. |
| `BOARD_DATA_SIZE` | `$40` | `ClearBoardData` / `ClearBoardDataLoop` clear `$40` bytes starting at `BOARD_DATA`; this matches `COLUMN_COUNT * BOARD_COLUMN_STRIDE`. |
| `BOARD_CELL_UNREAD_PAIR_OFFSET` | `$00` | In the current live source, the even byte of each two-byte board row pair is only cleared by `ClearBoardData`; no live piece/display/scan consumer reads or writes it as piece state. |
| `BOARD_CELL_VISIBLE_PAYLOAD_OFFSET` | `$01` | `DrawAllColumns` starts at `BOARD_DATA + $01`, so the odd byte in each two-byte row cell is the visible payload consumed by `DrawGridPiece`. |
| `BOARD_CELL_STRIDE` | `$02` | `DrawAllColumns` advances the source pointer by two bytes for each visible row. `FindBoardScanTargetRow` also advances the scanned row offset by two after each `ReadBoardCellAtColumnRow` probe. |
| `BOARD_ADJACENT_VISIBLE_CELL_DELTA` | `$02` | Alias for the one-visible-cell delta used when staging a landed payload above the current column top, comparing the already-filled B-type initial-board neighbor, and advancing the board-scan target probe to the next visible cell. |
| `BOARD_VISIBLE_ROW_COUNT` | `$07` | `DrawAllColumns` draws seven visible entries per column. |
| `BOARD_DRAW_FIRST_ROW` | `$02` | `DrawAllColumns` starts drawing each visible column at this row offset, and `UpdateFallingPieceMotionAndLanding` triggers `BuildGameOverPieceDisplayObjects` when a falling piece is still at this row before advancing. |
| `BOARD_COLUMN_BOTTOM_VISIBLE_OFFSET` | `$0D` | `FillInitialBoardColumns` / `FillInitialBoardCellLoop` fill initial pieces upward from `BOARD_COLUMN_BOTTOM_VISIBLE_CELL`, and `AnimateDropping` uses the same address as the bottom visible-cell base before applying the selected column stride. |
| `BOARD_COLUMN_END_SENTINEL_OFFSET` / `BOARD_FALL_END_ROW` | `$0F` | A-type setup seeds `COLUMN_TOP_ROWS` with this end-of-column offset, `FillInitialBoardColumns` returns immediately when the seed is already this value, B-type clear detection requires all four column rows to reach it, `HandleFallingPieceReachedColumn` skips landing-progress handling at this row, and `FindBoardScanTargetRow` stops scanning when `PIECE_FALL_POS` or the scan row reaches it. |
| `COLUMN_TOP_ROW_COMMIT_LIMIT` | `$10` | `CommitFallingPieceToBoard` returns without advancing the selected `COLUMN_TOP_ROWS` entry when it is already at this value. The exact higher-level condition still needs gameplay confirmation, so the name stays tied to the observed commit guard. |
| `COLUMN_TOP_ROW_OVERFLOW_SENTINEL` | `$FF` | After direct placement, `DrawLandedPieceAndUpdateColumnTop` lowers the selected `COLUMN_TOP_ROWS` entry by two row units; `$FF` means the decrement underflowed and branches into the game-over/result path. |
| `GRID_DRAW_ROW_LIMIT` | `$20` | `DrawGridPiece` ignores draw requests whose row coordinate is outside the 32-row BG-map coordinate range. |
| `GRID_PIECE_TILE_WIDTH` / `GRID_PIECE_TILE_ROWS` | `$04` / `$02` | `DrawGridPiece` copies two four-tile rows from `GridPiecePatternTable`; drop animation clears the same two-row height beside the moving piece. |
| `GRID_PIECE_NEXT_ROW_DELTA` | `$11` | After a four-byte tile row copy, `HL` points at the fourth tile. Adding `BG_MAP_ROW_STRIDE - 3` advances it to the same column on the next shadow BG-map row. |
| `GRID_COLUMN_CLEAR_TILE` | `$4A` | `ClearColumnLeft` / `ClearColumnRight` use this tile while clearing the one-tile side columns next to a moving 4x2 grid piece. |
| `GRID_PIECE_PATTERN_RECORD_SIZE` | `$08` | `GetGridPiecePatternOffset` multiplies the piece/display code by eight before indexing `GridPiecePatternTable`; `DrawGridPiece` copies two four-byte rows from that record. |
| `GRID_PIECE_PATTERN_PAYLOAD_COUNT` | `$09` | `GridPiecePatternTable` is now split into nine 8-byte payload records, covering the observed direct grid-piece pattern index range `0..8`. |
| `GRID_PIECE_PATTERN_*_TILE` | `$00-$23`, `$4A` | Tile IDs used inside the direct 4x2 `GridPiecePatternTable` records. The names stay scoped to record position and payload role because `DrawGridPiece` proves the copy layout, not the visual identity of each tile. |
| `BOARD_PAYLOAD_EMPTY` | `$00` | `ClearBoardData` clears all `BOARD_DATA` bytes to zero, and `GridPiecePatternTable` index 0 draws an all-blank tile block. |
| `BOARD_PAYLOAD_PIECE_1..6` | `$01-$06` | Board-cell payloads with direct 4x2 piece-pattern records. `$01-$04` are selected by the falling-piece display code path; `$05/$06` are currently confirmed through B-type initial-board generation and adjacent-duplicate adjustment. |
| `BOARD_PAYLOAD_SCAN_TRIGGER` / `BOARD_PAYLOAD_SCAN_TARGET` | `$07` / `$08` | Aliases behind `BOARD_SCAN_TRIGGER_PAYLOAD` and `BOARD_SCAN_TARGET_PAYLOAD`; these are the two special board-scan payloads with distinct grid-piece pattern records. |
| `BOARD_DRAW_FIRST_COLUMN` | `$00` | `DrawAllColumns` starts drawing the first column at column coordinate 0, then advances the draw column by `GRID_PIECE_TILE_WIDTH` after each board column. |
| `COLUMN_SPRITE_TOP_ROW_OFFSET` | `$03` | `DrawColumnSprite` begins drawing three tile rows above the current `COLUMN_TOP_ROWS` entry, matching `COLUMN_SPRITE_PATTERN_ROWS`. |
| `COLUMN_SPRITE_PATTERN_RECORD_SIZE` | `$0C` | `GetColumnSpritePatternOffset` multiplies the column index by twelve before indexing `ColumnSpritePatternTable`; `DrawColumnSprite` copies up to three four-byte rows from that record. |
| `COLUMN_SPRITE_FRAME_BLOCK_SIZE` | `$30` | `DrawColumnSprite` adds this to the pattern pointer when drawing the alternate column-blink frame, skipping the first four column records. |
| `COLUMN_SPRITE_PATTERN_FRAME_BLOCK_COUNT` / `COLUMN_SPRITE_PATTERN_LIVE_SIZE` | `$02` / `$60` | The live column-sprite range is two `$30`-byte frame blocks, each holding four 12-byte column records. |
| `COLUMN_SPRITE_PATTERN_UNREACHED_TAIL_SIZE` | `$10` | The final `$10` bytes are labeled separately as `UnreachedColumnSpritePatternTailRows` because the normal four-column/two-frame blink path does not index them. |
| `COLUMN_SPRITE_PATTERN_*_ENCODED_TILE` | `$49`, `$83-$B2` | Encoded bytes used by the live two-frame column-sprite records. `CopyEncodedTilePatternRow4SkipFF` writes each value plus one, so these constants deliberately name encoded source bytes rather than final BG tile IDs. |
| `UNREACHED_COLUMN_SPRITE_TAIL_*_TILE` | `$20-$27`, `$4A` | Scoped tile bytes for the four-row tail after the live column-sprite records. They are kept separate from the encoded live constants because no confirmed path indexes this tail. |
| `INITIAL_BOARD_PIECE_POOL_OFFSET` | `$03` | `FillInitialBoardCellLoop` shuffles `PIECE_DISPLAY_CODE_POOL` three times, then reads this pool entry for the next initial board cell. |
| `INITIAL_BOARD_PIECE_WRAP_SENTINEL` / `INITIAL_BOARD_PIECE_WRAP_CODE` | `$05` / `$01` | `AvoidInitialBoardAdjacentDuplicate` increments a generated initial-board code when it matches the cell two bytes ahead, and wraps only when the increment reaches `$05`. |
| `INITIAL_BOARD_FILL_VBLANK_WAIT_FRAMES` | `$0A` | `FillInitialBoardWithVBlankWait` stores this in `VBLANK_BUSY` before filling the initial board and waits for the VBlank countdown to reach zero. |
| `B_TYPE_INITIAL_PIECE_DISPLAY_COUNT` | `$02` | `InitBTypeFallTimingAndBoardSeed` seeds `PIECE_DISPLAY_COUNT` with this value before loading the column top-row seed from `BTypeColumnTopRowSeedTable`. |
| `BOARD_SCAN_TRIGGER_PAYLOAD` | `$07` | `UpdateFallingPieceMotionAndLanding` calls `RunBoardScanTriggerSequence` only for this staged payload, and `RunBoardScanTriggerSequence` redraws this payload while animating the scan. |
| `BOARD_SCAN_TARGET_PAYLOAD` | `$08` | `FindBoardScanTargetRow` scans the selected column for this payload, and `HandleMatchedLandingScanState` applies its unresolved landing-counter adjustment only for this staged payload. |
| `BOARD_SCAN_STEP_INITIAL` | `$00` | `RunBoardScanTriggerSequence` initializes the scan animation sound/step counter with this value before `BoardScanAnimationStepLoop`. |
| `BOARD_SCAN_BG_REFRESH_ROW` | `$03` | `RunBoardScanTriggerSequence` refreshes the game BG when the scan animation row reaches this row, one row below `BOARD_DRAW_FIRST_ROW`. |
| `BOARD_SCAN_STEP_MAX` | `$07` | `RunBoardScanTriggerSequence` increments its local sound/animation step counter up to this value; the same counter selects scan sounds from `SND_BOARD_SCAN_STEP_BASE` down to `SND_BOARD_SCAN_STEP_MIN`. |
| `BOARD_SCAN_SEND_FRAMES` | `$07` | Each `RunBoardScanTriggerSequence` animation step calls `Send2PData` for this many inner frames. |
| `BOARD_SCAN_SINGLE_STEP_DISTANCE` | `$01` | After deriving the scan distance, `RunBoardScanTriggerSequence` maps this single-step case to board-scan reward index zero; larger distances are stored directly in `BOARD_SCAN_REWARD_INDEX`. |
| `BOARD_SCAN_TRANSITION_FRAME_LIMIT_1..4` | `$01-$04` | `BoardScanTransitionFrameLimitTable` maps the saved board-scan reward index to the maximum round-transition sprite frame; `SendRoundTransitionFrameLoop` sends frames from `ROUND_TRANSITION_FRAME_START` through the selected limit. |

The board is currently best described as four 16-byte column blocks.
`FALLING_PIECE_GRID_COLUMN` is the staged sprite object's
`SPRITE_OBJECT_GRID_COLUMN` field, not a rotation field. Column selection uses
`FALLING_PIECE_GRID_COLUMN * $10` in
`StagePiecePayloadInSelectedColumn`; the scan path uses the same 16-byte column
stride in `ReadBoardCellAtColumnRow`. Row selection then adds the current
row/fall position within that block.

`BOARD_FALL_END_ROW` is an end-of-column row boundary for falling/scanning
rather than a confirmed piece value. A column with top-row state `$0F` is
treated as clear by the B-type completion check.

`DrawAllColumns` reads from `BOARD_DATA + BOARD_CELL_VISIBLE_PAYLOAD_OFFSET`,
draws seven entries per column through `DrawAllColumnsColumnLoop` /
`DrawAllColumnsRowLoop`, advances by two bytes per row, then skips two bytes
before the next column through `AdvanceDrawAllColumnsColumn`. The landing,
initial-fill, and board-scan paths now use
`BOARD_ADJACENT_VISIBLE_CELL_DELTA` for the same two-byte step when they need
the next visible cell above or below the current board row. The current live
board model is therefore single-byte visible payloads in the odd lane; the
paired even byte is now documented as `BOARD_CELL_UNREAD_PAIR_OFFSET` because
no live piece/display/scan consumer has been confirmed.

`BOARD_COLUMN_BOTTOM_VISIBLE_CELL` is `BOARD_DATA + $0D`, the last visible odd
offset in the first column block. Initial B-type board fill writes from this
cell upward by two bytes per row through `FillInitialBoardCellLoop`, and
`FillInitialBoardColumnLoop` advances by a 16-byte column stride. Drop
animation applies the same 16-byte stride from this base.

Initial B-type board setup seeds `PIECE_DISPLAY_COUNT` with
`B_TYPE_INITIAL_PIECE_DISPLAY_COUNT`, then indexes
`BTypeColumnTopRowSeedTable` by `ACTIVE_LEVEL` to choose the starting
`COLUMN_TOP_ROW_SEED`. The table entries are named as
`B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_0..4`, stepping upward from
`BOARD_COLUMN_BOTTOM_VISIBLE_OFFSET` by `BOARD_CELL_STRIDE` per level.
The fill loop chooses each generated cell from
`PIECE_DISPLAY_CODE_POOL + INITIAL_BOARD_PIECE_POOL_OFFSET` after three pool
shuffles. `AvoidInitialBoardAdjacentDuplicate` compares the candidate with the already-filled cell two
bytes ahead; a match increments the candidate, and the post-increment sentinel
`INITIAL_BOARD_PIECE_WRAP_SENTINEL` wraps back to
`INITIAL_BOARD_PIECE_WRAP_CODE`. This supports the current model that the
initial fill avoids a vertical adjacent duplicate while preserving the
two-byte row stride.

`DrawGridPiece` renders each payload as a 4x2 tile block. The row-advance delta
is `$11` because the four-byte copy leaves `HL` at the fourth tile of the row;
adding `GRID_PIECE_NEXT_ROW_DELTA` reaches the same column in the next 20-byte
shadow BG-map row. The visible payload footprint is explicit, and the paired
even byte is not part of the recovered live piece representation.
`DrawAllColumns` now reuses `BOARD_CELL_STRIDE` for both source-cell and
visible-row stepping, and `GRID_PIECE_TILE_WIDTH` for the next visible column.

The two board/tile pattern tables are now separated by consumer role.
`GridPiecePatternTable` is indexed by `GetGridPiecePatternOffset` with an
8-byte stride and copied directly through `CopyTilePatternRow4`. It is split
into `GridPiecePatternEmptyPayload`, `GridPiecePatternPiece1..6`,
`GridPiecePatternScanTrigger`, and `GridPiecePatternScanTarget` to match the
observed A-register payload range while preserving the two special scan
records. The rows now use `GRID_PIECE_PATTERN_ROW` with
`GRID_PIECE_PATTERN_*_TILE` constants: normal piece records share the four
frame-corner tiles and carry four payload-specific inner tiles, while the scan
records use blank outer columns plus their own inner tile pairs.
`ColumnSpritePatternTable` is indexed by `GetColumnSpritePatternOffset` with a
12-byte stride; `CopyEncodedTilePatternRow4SkipFF` stores each encoded byte
plus one, and skips writes for encoded `$FF` bytes. That conditional encoding
belongs to the column-blink sprite helper and is distinct from the direct grid
piece draw path. The live rows now use `COLUMN_SPRITE_PATTERN_ROW` with
`COLUMN_SPRITE_PATTERN_*_ENCODED_TILE` constants, including
`COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE` for the encoded blank tile byte. The
first `$30` bytes are the four records used for
`COLUMN_BLINK_FRAME_2`, the next `$30` bytes are the four records used for
`COLUMN_BLINK_FRAME_1`, and the final `$10` bytes are
`UnreachedColumnSpritePatternTailRows`, now expressed with
`COLUMN_SPRITE_PATTERN_ROW` and `UNREACHED_COLUMN_SPRITE_TAIL_*_TILE`
constants. The only confirmed
`DrawColumnSprite` caller is the four-slot column blink loop, so that live path
cannot select the tail records. `COLUMN_SPRITE_TOP_ROW_OFFSET` ties the three-row upward
starting offset to `COLUMN_SPRITE_PATTERN_ROWS`.

`UnusedFillBoardDataPattern` at `00:$09C8` is a coherent but currently
unreferenced board-fill fragment. It walks four chunks under `BOARD_DATA`,
clears a shrinking leading span from `UNUSED_BOARD_PATTERN_LEADING_CLEAR_BASE`,
writes the column index into a growing span, and stores a tail byte derived
from `UNUSED_BOARD_PATTERN_TAIL_BASE - column * 2`. No static caller or direct
branch target has been found, so it remains marked `Unused` rather than used as
evidence for the live board format or for the unread even board-cell lane.

## Playfield Side Panel Layout

`UpdateNextDisplay` builds the playfield side panel by filling the row 0,
column 16 rectangle with `PLAYFIELD_SIDE_PANEL_FILL_TILE`, then layering mode
dependent labels, HUD values, blank rows, bottom column markers, and 2P role
headers.

| Constant / Helper | Evidence |
|-------------------|----------|
| `PLAYFIELD_SIDE_PANEL_TOP_LEFT_COORD` / `PLAYFIELD_SIDE_PANEL_RECT_SIZE` | `UpdateNextDisplay` fills the 4x18 side-panel rectangle before drawing any labels or values. |
| `Draw1PPlayfieldSidePanelLabelRow0` | Skips 2P mode, then draws tile row `$30-$33` at the A-type or B-type row-0 label coordinate. |
| `DrawPlayfieldSidePanelLabelRow1` | Draws tile row `$38-$3B` at the 2P, A-type, or B-type row-1 label coordinate. |
| `DrawPlayfieldEggDisplay` / `DrawPlayfieldEggCountDigits` | A/B-type egg text and two-digit egg-count destinations are split between `PLAYFIELD_EGG_DISPLAY_*_COORD` and `PLAYFIELD_EGG_COUNT_*_COORD`. |
| `DrawPlayfieldBottomColumnMarkers` | Writes four repeated `$FB/$FC` tile pairs along row 16, aligned with the four playfield columns. |
| `BlankATypePlayfieldSidePanelRows` / `BlankBTypePlayfieldSidePanelRows` / `BlankTwoPlayerPlayfieldSidePanelRows` | Clear mode-specific unused side-panel rows with `PLAYFIELD_SIDE_PANEL_BLANK_TILE`. |

`FillTilemapRectByCoord` advances between shadow BG-map rows with
`BG_MAP_ROW_STRIDE - width`, where the row stride is the same
`BG_MAP_ROW_STRIDE` used throughout the `$C4A0-$C607` shadow tilemap.

## Main Consumers

- `ClearBoardData` clears the full `$40`-byte area through
  `ClearBoardDataLoop`.
- `SeedColumnTopRows` writes `COLUMN_TOP_ROW_SEED` into all four
  `COLUMN_TOP_ROWS` entries through `SeedColumnTopRowsLoop`.
- `FillInitialBoardWithVBlankWait` waits in
  `WaitInitialBoardFillVBlankLoop` after `FillInitialBoardColumns`.
- `DrawAllColumns` renders the visible board entries from the odd offsets.
- The even byte in each two-byte board row pair is not a live piece payload in
  the current trace. `ClearBoardData` clears it as part of the full board span,
  but the live draw, initial-fill, drop-swap, landing, and scan paths all use
  odd visible payload offsets or the `$0F` end sentinel.
- `ClearColumnLeftLoop` and `ClearColumnRightLoop` clear `GRID_PIECE_TILE_ROWS`
  entries with `GRID_COLUMN_CLEAR_TILE` in the one-tile columns adjacent to a
  board column after converting the row/column coordinate through
  `CalcTilemapAddress`.
- `FindBoardScanTargetRow` probes a selected column for
  `BOARD_SCAN_TARGET_PAYLOAD` through `FindBoardScanTargetRowLoop`, calling
  `ReadBoardCellAtColumnRow` at two-byte row intervals before either
  `ReturnBoardScanTargetRow` or `ReturnNoBoardScanTarget`.
- `ReadBoardCellAtColumnRow` computes the selected column block and row
  address through `StoreBoardColumnBaseLow` and
  `ReadBoardCellAtComputedAddress`.
- `RunBoardScanTriggerSequence` runs `BoardScanAnimationStepLoop`, draws the
  trigger payload with `DrawBoardScanTriggerPayload`, refreshes the BG at
  `BOARD_SCAN_BG_REFRESH_ROW`, and waits/sends through
  `SendBoardScanStepFrames` for each scan animation step. The derived scan
  distance uses `BOARD_SCAN_SINGLE_STEP_DISTANCE` as the special case that
  stages zero in `BOARD_SCAN_REWARD_INDEX`; larger distances are stored
  directly for the later `BoardScanRewardScoreDeltaTable` lookup.
- When `FindBoardScanTargetRow` returns no target,
  `RunBoardScanTriggerSequence` jumps to `FinishBoardScanNoTargetLanding`; that
  path spawns the landing field-column effect, clears the current gameplay
  object, plays `SND_PIECE_LAND`, and exits the falling-piece update without
  staging a board payload.
- `StagePiecePayloadInSelectedColumn` decrements the remaining-piece counter,
  reads the selected column row, compares the current board cell, and writes
  the staged piece payload one `BOARD_ADJACENT_VISIBLE_CELL_DELTA` step before
  that selected column/row position.
- `HandleFallingPieceReachedColumn` compares the staged payload with the
  current board cell. Matching non-terminal rows go through
  `HandleMatchedLandingScanState`; differing cells or the fall-end boundary go
  through `DrawLandedPieceAndUpdateColumnTop`.
- `DrawLandedPieceAndUpdateColumnTop` redraws the landed payload and lowers
  the selected `COLUMN_TOP_ROWS` entry by `BOARD_CELL_STRIDE` row units, with
  the `$FF` result (`COLUMN_TOP_ROW_OVERFLOW_SENTINEL`) entering the
  overflow/result path.
- `ClearLandedGameplayObject` is only a trampoline to
  `ClearCurrentGameplaySpriteObjectRecord`. The following one-byte `pop hl` is
  now labeled `UnreachedClearLandedGameplayObjectPop` because the visible
  landing and game-over/result paths all jump over it or return before it.
- `CommitFallingPieceToBoard` skips the top-row advance at
  `COLUMN_TOP_ROW_COMMIT_LIMIT`; otherwise it updates a `COLUMN_TOP_ROWS`
  entry, clears the drawn falling position, and calls
  `SpawnFieldColumnEffect`.
