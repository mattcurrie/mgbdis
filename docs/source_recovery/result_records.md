# Result Record State

The recovered result record area lives at `$C709-$C75C`.

## Records

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C709-$C729` | `A_TYPE_RESULT_RECORDS` | Three `RESULT_RECORD_SIZE` (`$0B`) records. `InitResultRecordsIfNeeded` initializes the first byte of each record to `RESULT_RECORD_EMPTY_HEAD` through `InitATypeResultRecord0`, `InitATypeResultRecord1`, and `InitATypeResultRecord2`; the result setup path starts `DrawStoredResultRecords` from this base when `GAME_TYPE` is zero. |
| `$C72A-$C74A` | `B_TYPE_RESULT_RECORDS` | Three `RESULT_RECORD_SIZE` records. The same setup path starts from this base when `GAME_TYPE` is nonzero. |
| `$C74B-$C755` | `CURRENT_RESULT_RECORD` | `ProcessCurrentResultRecordAndSetupScreen` stages the current score digits, displayed level digits, and A/B-specific detail digits here before comparing and inserting the record. |
| `$C756` | `RESULT_RECORDS_INIT_FLAG` | `InitResultRecordsIfNeeded` returns if this byte is nonzero; otherwise it seeds the six record heads and this flag with `RESULT_RECORD_EMPTY_HEAD`. The B-type record-head and flag tail is named `InitBTypeResultRecords`. |
| `$C757-$C75A` | `WRAM_PERSIST_MAGIC` | Startup checks bytes `$C7,$8A,$29,$36`; when they match, `WRAM_CLEAR_MODE_PRESERVE_RESULT_RECORDS` lets `ClearWRAMLoop` skip from `$C709` to `ROUND_END_WAIT_TIMER`, preserving the result records and magic. If they fail, `UseFullWRAMClear` selects `WRAM_CLEAR_MODE_FULL` and clears the full WRAM range. |
| `$C75B-$C75C` | `ROUND_END_WAIT_TIMER` | `ProcessRoundResultAndEnterRoundEnd` seeds this little-endian timer with `ROUND_END_WAIT_INITIAL_FRAMES` / `ROUND_END_WAIT_INITIAL_FRAMES_HI` (`$003C`); the 2P round-end path decrements it before continuing result flow. |

## Round-End Flow

`ProcessRoundResultAndEnterRoundEnd` exchanges or records the result code, clears the
round-complete object slots from `SPRITE_OBJECT_SLOT_10` for
`ROUND_COMPLETE_OBJECT_SLOT_CLEAR_BYTES` through
`ClearRoundCompleteObjectSlotsLoop`, stops the round/total timers, and enters
`GAME_STATE_ROUND_END` through
`EnterRoundEndState`. The 1P path plays `SND_RESULT_1P_RANKED` and draws the
rank immediately when `RESULT_RANK_POSITION` is nonzero; `RESULT_RANK_NONE`
selects `SND_RESULT_1P_NO_RANK`. The 2P path stores the exchanged result/rank
byte in `RESULT_RANK_POSITION`, then plays `SND_RESULT_2P_NONZERO_RANK` when it
is nonzero or `SND_RESULT_2P_ZERO_RANK` when it is zero before waiting for the
round-end timer. `QueueRoundResult` stores the code in
`ROUND_RESULT_CODE`, then raises `ROUND_RESULT_PENDING` and
`RESULT_FLOW_ACTIVE` with `RESULT_FLAG_SET`.
In the 2P B-type clear path, `UpdateGameplayObjectsAndCheckBTypeClear` queues
the nonzero round result, then the shared `ProcessBTypeClearRoundResult`
tail discards `RunGameplayFrame`'s return address before calling
`ProcessRoundResultAndEnterRoundEnd`; this skips the rest of the regular gameplay-frame tail
after result flow has been raised.
`DrawScoreRanking` renders the rank as two `RESULT_RANK_TILE_RUN_LENGTH` tile
runs using `RESULT_RANK_TOP_TILE_BASE` and `RESULT_RANK_BOTTOM_TILE_BASE`; the
special `RESULT_RANK_SPECIAL_POSITION_CODE` is normalized to
`RESULT_RANK_FIRST_PLACE` before the tile bases are applied.

`HandleRoundEnd` keeps the countdown digits visible while result flow finishes.
Single-player waits in `WaitRoundEndSoundFinishedLoop` for the active sound to
clear, then `WaitSinglePlayerRoundEndDelayLoop` waits
`ROUND_END_RESULT_DELAY_FRAMES` before `HandleSinglePlayerRoundCompleteFlow`
chooses the A/B-type tail.
The 2P path decrements `ROUND_END_WAIT_TIMER`, clears `SERIAL_DONE` /
`LINK_SEND`, waits `ROUND_END_RESULT_DELAY_FRAMES` in
`WaitTwoPlayerRoundEndDelayLoop`, and either resumes the next round or returns
to title through `ReturnRoundEndToTitle`.
The single-player A-type summary tail and the B-type no-rank tail share
`ClearRoundEndSpriteObjectsAndRecord`, which clears
`ROUND_END_SPRITE_OBJECT_CLEAR_BYTES` from `SPRITE_OBJECTS` before `ProcessCurrentResultRecordAndSetupScreen`
and `GAME_STATE_TITLE_INIT`.
The single-player game-over entry passes `RESULT_RANK_NONE` into
`ProcessRoundResultAndEnterRoundEnd`, while the 2P overflow path queues
`ROUND_RESULT_CODE_ZERO` through `QueueRoundResult`.

## Record Layout

Each stored record is `RESULT_RECORD_SIZE` bytes:

| Offset | Meaning |
|--------|---------|
| `+0..+4` | `RESULT_RECORD_SCORE_DIGIT_COUNT` low-nibble score digits copied from `SCORE_DIGITS`. |
| `+5` | `LEVEL_DISPLAY_TENS`; this is reached from the record head by `RESULT_RECORD_LEVEL_OFFSET`. |
| `+6` | `LEVEL_DISPLAY_ONES`. |
| `+7..+9` | `RESULT_RECORD_A_TYPE_DETAIL_DIGIT_COUNT` A-type egg count digits in hundreds/tens/ones order. |
| `+10` | A-type padding/ignored byte; `DrawStoredResultRecords` skips it after drawing the three egg digits. |
| `+7..+10` | `RESULT_RECORD_B_TYPE_DETAIL_DIGIT_COUNT` B-type total timer digits copied from `TOTAL_TIMER_DIGITS`. |

`ProcessCurrentResultRecordAndSetupScreen` stages the A-type detail digits through
`CopyATypeEggCountRemainingDigits` or the B-type timer digits through
`CopyBTypeResultTimerDigits`. `MaskCurrentResultRecordDigits` then masks all
`RESULT_RECORD_SIZE` staged bytes with `RESULT_RECORD_DIGIT_MASK` before
`ScanResultRecordInsertPositionLoop` scans `RESULT_RECORD_ROW_COUNT` entries,
starting from `RESULT_RECORD_FIRST_RANK`, and compares score, level, then
mode-specific detail bytes through `CompareResultRecordBytes`. If the staged
record ranks above an existing entry, `InsertCurrentResultRecordAtRank` shifts
the lower records down when needed and `CopyCurrentResultRecordToRankSlot`
copies `CURRENT_RESULT_RECORD` into the selected slot.
The down-shift uses `RESULT_RECORD_FIRST_RANK` to decide whether the top stored
record also has to move into row 1; lower insertions only shift the records below
the insertion point.

## Tilemap Display

`SetupResultRecordScreen` first loads the Bank 3 result tiles, builds the full
BG-map shadow frame, then renders stored records into the row area:

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C4B5` | `RESULT_RECORD_SCREEN_HEADER_TOP_LEFT` | The setup path fills a `RESULT_RECORD_SCREEN_HEADER_RECT_SIZE` header rectangle with `RESULT_RECORD_SCREEN_HEADER_TILE` after clearing the full `BG_MAP_SHADOW` with `RESULT_RECORD_BG_SHADOW_CLEAR_TILE`. |
| `$C4F7/$C4F8` | `RESULT_RECORD_TYPE_LABEL_TOP_LEFT` / `RESULT_RECORD_B_TYPE_LABEL_PATCH` | A six-tile type label is filled with `RESULT_RECORD_TYPE_LABEL_TILE`; B-type patches the second tile to `RESULT_RECORD_B_TYPE_LABEL_PATCH_TILE`. |
| `$C504` | `RESULT_RECORD_BOX_TOP_LEFT` | `FillResultRecordBoxRow` draws an 8-row record frame here: one top row, six body rows, and one bottom row. |
| `$C51D` | `RESULT_RECORD_COLUMN_HEADER_TOP_LEFT` | The column header row is filled with `RESULT_RECORD_COLUMN_HEADER_TILE` before the A/B-specific detail blocks are selected. |
| `$C527` | `RESULT_RECORD_B_TYPE_HEADER_PATCH_TOP_LEFT` | B-type overwrites a three-tile section of the column header with `RESULT_RECORD_B_TYPE_HEADER_PATCH_TILE`. |
| `$C5A6/$C5B0` | `RESULT_RECORD_A_TYPE_DETAIL_LEFT/RIGHT_TOP_LEFT` | A-type draws two lower detail panels with tile bases `$4B` and `$57` before `RenderStoredResultRecords`. |
| `$C5A6/$C5DA` | `RESULT_RECORD_B_TYPE_DETAIL_TOP_LEFT` / `RESULT_RECORD_B_TYPE_MARK_TOP_LEFT` | `DrawBTypeResultRecordDetailLayout` reuses the left detail-panel origin for a wider tile `$7C` block and draws a 2x2 mark block with tile `$90`. |

`FillResultRecordBoxBodyRows` emits the six middle rows between the top and
bottom frame rows by repeatedly calling `FillResultRecordBoxRow`.

The result record screen uses three two-row-spaced record lines:

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C52D/$C555/$C57D` | `RESULT_RECORD_LABEL_ORIGIN_0..2` | The setup path fills the three 3-tile labels with `$38/$3B/$3E`, and `WaitResultRecordScreenInput` blinks one selected label with `$94/$97/$9A` until input. The blink uses `STATE_TRANSITION` as a frame counter, switches back to the normal label at `RESULT_RECORD_LABEL_BLINK_ALT_START_FRAME`, and wraps at `RESULT_RECORD_LABEL_BLINK_PERIOD`. |
| `$C530` | `RESULT_RECORD_VALUE_TOP_LEFT` | `DrawStoredResultRecords` renders each record from this origin. After writing one row's variable-width fields, it advances by `RESULT_RECORD_NEXT_RENDER_ROW_DELTA` to reach the next stored record row. |
| `$C534/$C538/$C53D` | `RESULT_RECORD_*_PLACEHOLDER_ORIGIN` | `FillResultRecordPlaceholderColumn` writes `RESULT_RECORD_PLACEHOLDER_TILE` down all three result rows before stored records are rendered over it. |

`DrawStoredResultRecords` emits five score digits
(`RESULT_RECORD_SCORE_DIGIT_COUNT`), two level digits
(`RESULT_RECORD_LEVEL_DIGIT_COUNT`), and either three A-type egg/count digits
(`RESULT_RECORD_A_TYPE_DETAIL_DIGIT_COUNT`) or two B-type timer digit pairs
(`RESULT_RECORD_B_TYPE_TIMER_PAIR_DIGIT_COUNT`). `DrawResultRecordDigitRun`
masks stored packed digits with `RESULT_RECORD_DIGIT_MASK`, converts them to
result-screen tile IDs by adding `RESULT_RECORD_DIGIT_TILE_BASE`, and uses
`RESULT_RECORD_SUPPRESS_LEADING_ZEROES` / `RESULT_RECORD_SHOW_LEADING_ZEROES`
as the leading-zero policy. When suppression reaches
`RESULT_RECORD_FINAL_DIGIT_REMAINING`, the helper still emits
`RESULT_RECORD_DIGIT_TILE_BASE` so an all-zero run displays one zero. B-type
detail rendering inserts `RESULT_RECORD_TIMER_SEPARATOR_TILE` between the two
timer digit pairs.

Before accepting input, `FadeInResultRecordPalette` applies the four-entry
`ResultRecordPaletteSequence`, whose entries are emitted as
`RESULT_RECORD_PALETTE_FADE_STEP` records named
`RESULT_RECORD_PALETTE_FADE_VALUE_0..3`, using
`RESULT_RECORD_PALETTE_FADE_STEP_COUNT`, waiting
`RESULT_RECORD_PALETTE_FADE_WAIT_FRAMES` VBlanks between palette writes.
