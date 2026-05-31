# Sprite / OAM Recovery Notes

This document records the current evidence for the logical sprite object buffer,
shadow OAM, and Bank 1 sprite update tables.

## Runtime Buffers

| Range | Name | Confidence | Evidence |
|-------|------|------------|----------|
| `$C200-$C2FF` | `SPRITE_OBJECTS` | High | `UpdateSprites` scans 16 slots by loading `D=$C2`, adding `$10` to the low byte each iteration, and stopping when the low byte wraps to `SPRITE_OBJECT_SCAN_END_OFFSET`. |
| `$C400-$C49F` | `SHADOW_OAM` | High | `ClearOAM` clears `$A0` bytes through `ClearShadowOamLoop`; `HideAllSprites` writes hidden Y to each entry through `HideShadowOamSpritesLoop`; the HRAM OAM DMA routine copies page `$C4` to hardware OAM. |
| `$FF8E` | `SPRITE_SCAN_SLOT_OFFSET` | High | Temporary slot offset while `UpdateSprites` scans `$C200`, `$C210`, ..., `$C2F0`. |
| `$FF8F` | `SHADOW_OAM_WRITE_OFFSET` | High | Temporary OAM write offset while `UpdateSprites` appends expanded hardware sprite entries. |
| `$FF90/$FF91` | `SPRITE_BASE_X_TMP` / `SPRITE_BASE_Y_TMP` | High | Per-object base position loaded from object slot offsets `$06` and `$04`; `UpdateSprites` adds the Game Boy OAM hardware biases `$08/$10`. |
| `$FF92` | `SPRITE_OBJECT_ATTR_TMP` | Medium | Stores object type bit `$80`, later ORed into per-sprite attributes when the layout attribute byte has bit 1 set. |
| `$FF96` | `SPRITE_OBJECT_SLOT_OFFSET_TMP` | High | `UpdateSpriteObject` stores the selected `$C2xx` slot offset before copying the staged object back. |
| `$C68B` | `SPRITE_OBJECT_STAGING_INDEX` | High | `UpdateSpriteObject` saves its input index here; `ClearCurrentGameplaySpriteObjectRecord` uses it to clear the same gameplay object record. |
| `$C68C-$C695` | `SPRITE_OBJECT_STAGING` | High | `UpdateSpriteObject` copies 10 bytes from one `$C2xx` slot into this work area, updates movement/state fields, then copies the 10-byte record back. |

`ClearSpriteObjectBuffer` clears `SPRITE_OBJECT_BUFFER_CLEAR_BYTES` bytes
starting at `SPRITE_OBJECTS` before the playfield UI and gameplay sprite
producers rebuild the active logical object slots.
The renderer scan terminates at `SPRITE_OBJECT_SCAN_END_OFFSET`, the low-byte
wrap produced after `SPRITE_OBJECT_COUNT` 16-byte slots.

## Hardware OAM Entry Format

Each shadow OAM entry is four bytes:

| Offset | Name |
|--------|------|
| `+0` | `OAM_Y_OFFSET` |
| `+1` | `OAM_X_OFFSET` |
| `+2` | `OAM_TILE_ID_OFFSET` |
| `+3` | `OAM_ATTR_OFFSET` |

The matching/result animation code writes `MatchingOamTemplateTop`,
`MatchingOamTemplateMiddle`, and `MatchingOamTemplateFinal` into `SHADOW_OAM`
or `SHADOW_OAM_ENTRY_2`, then adjusts entry X and tile fields through
`OAM_X_OFFSET` / `OAM_TILE_ID_OFFSET`.
The middle template is four hardware OAM entries
(`MATCHING_MIDDLE_OAM_ENTRY_COUNT`), while the top and final pair templates are
two entries each (`MATCHING_PAIR_OAM_ENTRY_COUNT`).
Their entries are emitted with `OAM_TEMPLATE_ENTRY y, x, tile, attr`; the
arguments name the observed OAM Y/X coordinates, initial tile IDs, and
`OAM_ATTR_NONE`. The middle and final template tile IDs are then rewritten from
the matching tile-base table before display.
`MatchingTileBaseIndexTable` entries are scaled by
`MATCHING_MIDDLE_OAM_TILE_INDEX_SHIFT` for the middle four-entry template and
by `MATCHING_FINAL_OAM_TILE_INDEX_SHIFT` for the final two-entry template.
The table values are named as `MATCHING_TILE_BASE_INDEX_STATE_0..27`, keeping
the names tied to the `STATE_TRANSITION` index rather than claiming individual
sprite meanings for the repeated tile groups.
`DrawPauseOverlay` copies `PauseOverlayOamTemplate` directly to `SHADOW_OAM`;
it is eight hardware OAM entries (`PAUSE_OVERLAY_OAM_ENTRY_COUNT`), or
`PAUSE_OVERLAY_OAM_TEMPLATE_SIZE` bytes.
The eight pause `OAM_TEMPLATE_ENTRY` records share `PAUSE_OVERLAY_OAM_Y`,
advance from `PAUSE_OVERLAY_OAM_X_0` through `PAUSE_OVERLAY_OAM_X_7`, use
`PAUSE_OVERLAY_OAM_TILE_0..7`, and set `PAUSE_OVERLAY_OAM_ATTR` to the DMG
palette-1 attribute value.
The `ProcessMatching` local labels now separate the middle-template tile-ID
rewrite (`FillMatchingMiddleOamTileIdsLoop`), the top-pair slide
(`SlideMatchingTopOamRightLoop`), the combined left slide
(`SlideMatchingOamTogetherLeftLoop` / `ShiftMatchingMiddleOamLeftLoop`), and
the final two-entry upward move (`MoveMatchingFinalOamUpLoop`).
`MATCHING_OAM_SLIDE_FRAMES`, `MATCHING_OAM_X_STEP_RIGHT`, and
`MATCHING_OAM_X_STEP_LEFT` name the eight-frame horizontal slide, while
`MATCHING_FINAL_OAM_UP_FRAMES` names the final upward movement length.

## Logical Object Slot Format

Each slot is `$10` bytes. `InitSpriteBuffer` clears the first byte of every
slot; a zero type disables the object.

| Offset | Meaning | Evidence |
|--------|---------|----------|
| `+$00` | Object type / high-bit attribute source | Read first. If zero, the slot is skipped. Bit `$80` is saved in `SPRITE_OBJECT_ATTR_TMP` for possible attribute inheritance; for values `$81-$87`, the later `dec` + `sla` indexing drops bit 7 so they share the `$01-$07` frame-table entries. |
| `+$01` | Unused/padding byte in current trace | `UpdateSprites` skips from type `+$00` directly to frame `+$02`, and `UpdateSpriteObject` does not inspect this byte in the staged gameplay record. Settings cursor templates initialize it with `SPRITE_OBJECT_UNUSED_1_INIT_VALUE` (`$00`), but no independent consumer has been confirmed. |
| `+$02` | Animation frame index | If `SPRITE_OBJECT_FRAME_DISABLED`, the slot is skipped. Otherwise multiplied by 4 and used to pick a frame record from the selected frame table. |
| `+$03` | Toggled frame shadow for option BGM cursor slots | Settings cursor templates initialize `+$02` and `+$03` to the same frame value. `ApplySoundVisualUpdateCommand` selects slot `BGM_CURSOR_OBJECT_SLOT_BASE + OPTION_BGM`, toggles `+$03` with `BGM_CURSOR_FRAME_TOGGLE_MASK`, and copies the result into `+$02` only while the BGM option row is selected. |
| `+$04` | Base Y | Added to each layout Y delta plus OAM bias `$10`. |
| `+$05` | Grid/collision column | For active gameplay slots, `InitActivePieceDisplayObject` writes the display slot index here, `UpdateDropPositions` derives it from `Base X / $20` when the byte is `SPRITE_OBJECT_GRID_COLUMN_UNSET`, and `CheckDropCollisionAgainstActiveObjects` compares it with the drop-animation column. |
| `+$06` | Base X | Added to each layout X delta plus OAM bias `$08`. |
| `+$07` | Delay counter | `UpdateSpriteObject` decrements this field while `SPRITE_OBJECT_PHASE` is `$01`; when it reaches zero, the routine reloads it from `SPRITE_OBJECT_DELAY_RELOAD` and advances the phase to `$02`. `InitActivePieceDisplayObject` initializes piece-display objects with `PIECE_DISPLAY_OBJECT_INITIAL_DELAY`. |
| `+$08` | Object phase | `0` disables the producer-side update, `$01` waits on `SPRITE_OBJECT_DELAY_COUNTER`, and `$02` enters `UpdateFallingPieceMotionAndLanding`; `HandlePlayfieldInput` / `CheckFastFallActiveSlots` test slots 1-4 for phase `$02` before clamping the drop timers. |
| `+$09` | Tile / piece payload | In the staged `$C695` byte, `UpdateFallingPieceMotionAndLanding` passes this value to `DrawGridPiece`, writes it back into `BOARD_DATA`, and compares `BOARD_SCAN_TRIGGER_PAYLOAD` / `BOARD_SCAN_TARGET_PAYLOAD` for scan/landing behavior. `InitActivePieceDisplayObject` also writes this byte as the visible piece payload. |
| `+$0F` | Fast-fall clamp byte | `ClampGameplayObjectFastFallLoop` walks slots 1-4 at `SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE` and caps the byte to `PIECE_FAST_FALL_TIMER_CLAMP` when Down is held and any gameplay object slot is in update phase. No independent consumer or initializer has been confirmed, so the name remains narrow and low confidence. |

The remaining slot bytes outside this table are not fully mapped and still need
dedicated traces before they get broad semantic names.

## Object Producers

`UpdateSpriteObject` is the first confirmed producer-side bridge for gameplay
object slots. Its input `A` selects slots `$C210`, `$C220`, `$C230`, and
`$C240` by computing `(A + 1) * $10`. The routine copies 10 bytes from that
slot into `SPRITE_OBJECT_STAGING`, updates state through `UpdateFallingPieceMotionAndLanding` or
the slot-local `SPRITE_OBJECT_DELAY_COUNTER`, then copies the same 10-byte
record back to the selected slot. `ClearCurrentGameplaySpriteObjectRecord` uses
the saved index, and `ClearGameplayObjectRecordLoop` clears the selected
10-byte record when the object finishes.
The staged gameplay bytes are now named as offsets: `SPRITE_OBJECT_GRID_COLUMN`
(`+$05`),
`SPRITE_OBJECT_DELAY_COUNTER` (`+$07`), `SPRITE_OBJECT_PHASE` (`+$08`), and
`SPRITE_OBJECT_TILE_ID` (`+$09`, address `$C695` while staged). The staged copy
also includes `SPRITE_OBJECT_UNUSED_1` (`+$01`) and
`SPRITE_OBJECT_TOGGLED_FRAME` (`+$03`), but no gameplay-side consumer is
confirmed for either byte.

`UpdateDropPositionsLoop` walks the active gameplay slots and fills
`SPRITE_OBJECT_GRID_COLUMN` from base X when the field is
`SPRITE_OBJECT_GRID_COLUMN_UNSET`; otherwise it leaves the explicit grid column
intact and advances at `AdvanceDropPositionSlot`. Drop collision paths set the
field to this sentinel after shifting `SPRITE_OBJECT_BASE_X` by
`DROP_COLLISION_SPRITE_X_STEP`.

`SPRITE_OBJECT_DELAY_RELOAD` (`$C66E`) is initialized to `1` by
`ResetTitleState` and copied into each staged object's `+$07` delay counter when
`TickSpriteObjectWaitPhase` advances a waiting slot from phase `$01` to phase
`$02`. `WriteBackSpriteObjectStaging` then copies the updated staged record
back to the selected `$C2xx` object slot.

Confirmed slot groups:

| Slot/range | Current evidence |
|------------|------------------|
| Slot 0 (`$C200`) | `InitPlayerCursorObject` initializes `SPRITE_OBJECT_TYPE_PLAYER_CURSOR`, `PLAYER_CURSOR_INITIAL_FRAME`, `PLAYER_CURSOR_INITIAL_BASE_Y`, and `PLAYER_CURSOR_INITIAL_BASE_X`; it also seeds `FIELD_COLUMN_TILE_PATTERN_INDEX` with `FIELD_COLUMN_TILE_PATTERN_INITIAL_INDEX`. `SetPlayfieldCursorSlotType` restores the type byte during playfield board/piece setup. `UpdateDropCursorAnimation` advances its frame, and left/right input adjusts base X by `PLAYER_CURSOR_X_STEP`. |
| Slots 1-4 (`$C210-$C24F`) | `UpdateGameplayObjectsAndCheckBTypeClear` walks `UpdateGameplayObjectSlotsLoop`, calling `UpdateSpriteObject` for `SPRITE_OBJECT_ACTIVE_SLOT_COUNT` gameplay indices; `CheckGameplayObjectSlotsActive` / `ScanGameplayObjectSlotsLoop` then reports `GAMEPLAY_OBJECTS_ACTIVE` when any of these slots is still active. Collision/drop code scans the same four slots and uses `SPRITE_OBJECT_GRID_COLUMN`, `SPRITE_OBJECT_PHASE`, and the low-confidence `SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE`. |
| Slots 5-8 (`$C250-$C28F`) | `BuildGameOverPieceDisplayObjectSlotsLoop` writes `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` into these slots from `PIECE_DISPLAY_STATES`, using the state byte as the frame and deriving base X from the reverse display index. `GAME_OVER_PIECE_DISPLAY_SLOT_OFFSET` maps the four display-state entries onto these slots. `ClearPieceDisplayObjectSlotsLoop` clears the producer-visible type/frame bytes for these slots before rebuilding display state, advancing by `PIECE_DISPLAY_OBJECT_CLEAR_SLOT_ADVANCE` after the frame byte. |
| Slots 9-13 (`$C290-$C2DF`) | Options cursors, round-complete animations, countdown digits, and 2P field transition objects use these slots. `InitRoundCompleteTileSlotsLoop` builds `ROUND_COMPLETE_TILE_SLOT_COUNT` 2P round-complete tile slots from slot 9's base position, while single-player `ProcessRoundComplete` uses `InitRoundCompleteTileSlotsFromBaseLoop` to build the same count from `ROUND_COMPLETE_TILE_BASE_Y` / `ROUND_COMPLETE_TILE_BASE_X`. `SpawnFieldColumnEffect` creates `SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT` in slot `10 + FALLING_PIECE_GRID_COLUMN`, and `ClearExpiredFieldColumnEffect` clears timed slots through the shared `SPRITE_OBJECTS_HI` page. |

`ClearPieceSpriteObjectSlots` clears `PIECE_SPRITE_OBJECT_SLOT_COUNT` slots
starting at `SPRITE_OBJECT_SLOT_1`, so `PIECE_SPRITE_OBJECT_CLEAR_BYTES`
covers the gameplay piece slots 1-4 plus the piece-display/game-over display
slots 5-8.

`ProcessRoundResultAndEnterRoundEnd` clears `ROUND_COMPLETE_OBJECT_SLOT_CLEAR_BYTES` starting
at `SPRITE_OBJECT_SLOT_10`, covering slots 10-13 before entering the round-end
result flow.

`ClearRoundEndSpriteObjectsAndRecord` clears
`ROUND_END_SPRITE_OBJECT_CLEAR_BYTES` from `SPRITE_OBJECTS` before calling
`ProcessCurrentResultRecordAndSetupScreen` and returning to the title init state.

Confirmed object types:

| Type | Constant | Evidence |
|------|----------|----------|
| `$00` | `SPRITE_OBJECT_TYPE_NONE` | `UpdateSprites` skips zero type bytes, `InitSpriteBuffer` clears each logical slot type to zero, and the round-transition path clears slot 9 with this value after applying the reward. |
| `$01` | `SPRITE_OBJECT_TYPE_PLAYER_CURSOR` | Slot 0 setup and left/right input path. |
| `$02` | `SPRITE_OBJECT_TYPE_PIECE_DISPLAY` | Written by `InitActivePieceDisplayObject` into slots 1-4 and by `BuildGameOverPieceDisplayObjects` into slots 5-8 from `PIECE_DISPLAY_STATES`; this object type is the piece-display builder used by the display-results and game-over paths. |
| `$03` | `SPRITE_OBJECT_TYPE_ROUND_TRANSITION` | Written to slot 9 during the round-complete / 2P transition path; its base X is offset with `ROUND_TRANSITION_BASE_X_OFFSET`, the path sends `ROUND_TRANSITION_PRE_FRAME_0` and `ROUND_TRANSITION_PRE_FRAME_1` for `ROUND_TRANSITION_PRE_FRAME_SEND_FRAMES` each, then `SendRoundTransitionFrameLoop` advances its frame values during the send/wait sequence before toggling the frame with `ROUND_TRANSITION_FRAME_TOGGLE_MASK` and choosing the reveal sound. |
| `$04` | `SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE` | Written to slots 10-13 by `ProcessRoundComplete` and the 2P round-complete path; the 2P path mirrors slot 9's base coordinates through `InitRoundCompleteTileSlotsLoop`, while the single-player path copies `ROUND_COMPLETE_TILE_BASE_Y` / `ROUND_COMPLETE_TILE_BASE_X` through `InitRoundCompleteTileSlotsFromBaseLoop`. |
| `$05` | `SPRITE_OBJECT_TYPE_SETTINGS_CURSOR` | Used by `SettingsCursorSpriteInit0` through `SettingsCursorSpriteInit2`. |

`ClearSettingsCursorFrameHighBits` runs after accepted 1P pre-play input. It
walks `SETTINGS_CURSOR_OBJECT_COUNT` slots starting at `SPRITE_OBJECT_SLOT_9`
and masks each `SPRITE_OBJECT_FRAME` with `SETTINGS_CURSOR_FRAME_LOW_MASK`,
normalizing the three initialized settings cursor objects after the BGM cursor
frame toggle path.

`ApplySettings` copies `SETTINGS_CURSOR_INIT_COPY_SIZE` bytes from
`SettingsCursorSpriteInit0..2` into slots 9-11. The source emits each one with
`SETTINGS_CURSOR_INIT_RECORD frame, base_x`, initializing the settings cursor
type, the visible frame and toggled-frame shadow, a shared base Y, an
unused/grid-column byte, and the three base-X positions used by the 1P BGM
marker cursor objects.
| `$06` | `SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT` | Created by `SpawnFieldColumnEffect` in slot `10 + FALLING_PIECE_GRID_COLUMN` after a committed or landed piece. The frame argument is `FIELD_COLUMN_EFFECT_FRAME_COMMIT` for the commit path and `FIELD_COLUMN_EFFECT_FRAME_LAND` for the landing path; `FIELD_COLUMN_TIMERS` keeps the object visible briefly before `ClearSpriteObjectSlot` removes it. |
| `$07` | `SPRITE_OBJECT_TYPE_RESERVED_7` | `SpriteUpdatePointerTable` has a frame-table entry that draws two tile `$E0` sprites with `SpriteLayout_ReservedObject7`, but the current source has no confirmed producer that writes `$07` as a logical sprite object type. |

## Sprite Update Table Format

`SpriteUpdatePointerTable` is indexed by `object_type - 1` after `UpdateSprites`
saves object type bit `$80` to `SPRITE_OBJECT_ATTR_TMP`. For valid high-bit
values `$81-$87`, the following `sla a` drops bit 7 from the table offset, so
they select the same frame-table entries as `$01-$07` while optionally supplying
an inherited OAM attribute bit. The current producer search found no writer for
high-bit logical sprite object types.

In source, the formerly flat `01:$40A0-$42F4` payload is split into:

| Label family | Meaning |
|--------------|---------|
| `SpriteUpdatePointerTable` | Object type to frame-table records emitted with `SPRITE_OBJECT_FRAME_TABLE object_type, frame_table`. |
| `SpriteFrameTable_*` | Per-object animation frame records emitted with `SPRITE_FRAME_RECORD tile_id_list, layout_list`. High-confidence object types now use semantic suffixes; reserved type `$07` has a frame-table entry but no confirmed producer. |
| `SpriteTileList_*` | Tile IDs read sequentially, emitted as `SPRITE_TILE_LIST_N` with one byte for each emitted hardware sprite. |
| `SpriteLayout_*` | Repeated `SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr` triples. |

The player cursor frame records now name the five distinct tile lists
(`SpriteTileList_PlayerCursorFrame0..4`) and the three cursor layouts
(`SpriteLayout_PlayerCursorSixTile`,
`SpriteLayout_PlayerCursorFourTileForward`, and
`SpriteLayout_PlayerCursorFourTileFlipped`) used by
`SpriteFrameTable_PlayerCursor`. The round-complete tile frame records now
name their shared tile list (`SpriteTileList_RoundCompleteTile`) and the four
normal / X-flip / Y-flip / XY-flip layouts used by
`SpriteFrameTable_RoundCompleteTile`.
The settings cursor frame records now name their normal and alternate tile
lists (`SpriteTileList_SettingsCursorFrame*`), all using the shared
`SpriteLayout_TwoTileRow`. The round-transition object similarly names the
normal and alternate transition tile lists and the two/four/six/eight-hardware
sprite layouts used by `SpriteFrameTable_RoundTransition`.
The piece-display frame records now use frame-index labels
(`SpriteTileList_PieceDisplayFrame*`) and
`SpriteLayout_PieceDisplayTwoTileRow`. The older `GameOverPiece` wording was
too narrow: `SpriteUpdatePointerTable` dispatches
`SPRITE_OBJECT_TYPE_PIECE_DISPLAY` to this frame table, and both active
piece-display and game-over/display paths produce that object type.

Each `SPRITE_FRAME_RECORD` emits a 4-byte frame table entry:

```text
dw tile_id_list, layout_list
```

`tile_id_list` is emitted with a count-specific `SPRITE_TILE_LIST_N` macro and
read one byte per emitted hardware sprite. The intentionally overlapping
`SpriteTileList_PieceDisplayFrame22` label still shares the first two bytes of
`SpriteLayout_TwoTileRow`, matching the original pointer target.
`layout_list` is read as repeated `SPRITE_LAYOUT_ENTRY` triples:

```text
SPRITE_TILE_LIST_N tile0[, tile1...]
SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr
```

The `attr` arguments use `OAM_ATTR_*` / `OAMF_*` hardware bits plus
`SPRITE_LAYOUT_ATTR_END` and `SPRITE_LAYOUT_ATTR_INHERIT` for the renderer's
local control bits.

The emitted hardware OAM entry is:

```text
Y    = object_base_y + $10 + y_delta
X    = object_base_x + $08 + x_delta
Tile = *tile_id_list++
Attr = attr, optionally ORed with the saved object `$80` bit when `attr` bit 1 is set
```

`attr` bit 0 (`SPRITE_LAYOUT_ATTR_END`) terminates the layout list after the
current hardware sprite has been emitted. `attr` bit 1
(`SPRITE_LAYOUT_ATTR_INHERIT`) requests ORing the saved object `$80` bit into
the emitted OAM attribute byte.

The board/tile sprite helpers use a separate four-byte tile-row format.
`GridPiecePatternTable` stores direct 8-byte records consumed by
`GetGridPiecePatternOffset` and `CopyTilePatternRow4`, now labeled as
`GridPiecePatternEmptyPayload`, `GridPiecePatternPiece1..6`,
`GridPiecePatternScanTrigger`, and `GridPiecePatternScanTarget`.
`ColumnSpritePatternTable` stores two `$30`-byte frame blocks of four 12-byte records each, plus a separate 16-byte tail labeled
`UnreachedColumnSpritePatternTailRows`. The 12-byte records are consumed by
`GetColumnSpritePatternOffset` and `CopyEncodedTilePatternRow4SkipFF`; the
encoded-copy helper increments each source byte and skips writes where the
encoded byte was `$FF`. The skip/advance labels are named
`AdvanceAfterConditionalSpriteByte0..2` and
`ReturnAfterConditionalSpriteBytes`.

Inside `DrawColumnSprite`, `UnreachedColumnSpriteAlternateRowFragment` is
currently static-dead: an unconditional branch to `DrawColumnSpriteRow0`
precedes it, and the only confirmed caller reaches `DrawColumnSprite` from the
four-slot column blink loop. The fragment's internal labels are therefore kept
with an `UnreachedColumnSprite*` prefix rather than being used as evidence for
the live column-sprite table range.

Some labels intentionally overlap because the original data reuses subranges.
For example, `SpriteLayout_FieldColumnEffectUpper` starts inside
`SpriteLayout_FieldColumnEffectLower`, and
`SpriteTileList_PieceDisplayFrame22` shares its address with
`SpriteLayout_TwoTileRow`.

## Redraw Gate

`LCD_REDRAW` controls `UpdateSprites`:

| Value before `UpdateSprites` | Behavior |
|------------------------------|----------|
| `LCD_REDRAW_EXPAND_REQUEST` | Expand logical object slots into shadow OAM. |
| `LCD_REDRAW_HIDE_ALL_REQUEST` | Set `LCD_REDRAW` to `LCD_REDRAW_HIDE_ALL_SENTINEL` and hide all sprites. |
| Other | Return without changing OAM. |

Title/playfield setup, unpause, and game-tile reload paths store
`LCD_REDRAW_EXPAND_REQUEST` explicitly before the next `UpdateSprites` pass.
Matching/result-screen setup paths still use `xor a` to request hide-all without
changing instruction size.

After expanding active logical objects, unused shadow OAM entries are hidden by
writing Y=`$A0` until offset `$98`. The direct "full hide" routine writes
Y=`$A0` for all 40 hardware sprites.

Inside the expansion path, `ScanSpriteObjectSlotLoop` walks the 16 logical
object slots, `DrawSpriteObjectOamEntryLoop` emits one or more hardware OAM
entries for the selected frame, and `HideUnusedShadowOamLoop` hides any
remaining automatic entries up to the `$98` limit. `InitSpriteBuffer` uses
`ClearSpriteObjectSlotTypesLoop` to clear the first byte of each logical slot.

`SHADOW_OAM_MANUAL_PAIR` (`$C498`) is the two-entry tail just after that
automatic hide limit. `AddScoreAndAnimateManualOamPair` clears those two
hardware OAM entries, calls `AddScore` with the score value in `HL`, stages a
two-tile bonus sprite at the round-complete X/Y position, and moves both
entries upward for `ROUND_COMPLETE_BONUS_ANIM_FRAMES` before waiting
`ROUND_COMPLETE_BONUS_HOLD_FRAMES`. The left tile/Y/score come from the
500/200/100/50-point reveal constants; the right tile is fixed as
`ROUND_COMPLETE_BONUS_RIGHT_TILE` at
`ROUND_COMPLETE_BONUS_RIGHT_TILE_X_STEP` pixels to the right.

The round-complete tilemap boxes at `ROUND_COMPLETE_TILEMAP_ORIGIN_0..3`
trigger the matching sprite groups by calling `ShowRoundComplete` with base X
values `ROUND_COMPLETE_TILE_BASE_X_0..3`; `ProcessRoundComplete` then writes
`SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE` into logical sprite slots 10-13 using
`ROUND_COMPLETE_TILE_GROUP_BASE_Y` for the shared Y coordinate.
For the A-type round-complete summary, `ShowRoundComplete` also indexes
`RoundCompleteRevealThresholdTable` by `ROUND_COMPLETE_REVEAL_THRESHOLD_RECORD_SHIFT`
to choose the reveal stage from the named
`ROUND_COMPLETE_REVEAL_INDEX_*_{500,200,100,50}_THRESHOLD` entries, and the
final stage indexes `RoundCompleteFinalTileTable` to fill the current 2x2
tilemap box with one of `ROUND_COMPLETE_FINAL_TILE_INDEX_0..6`.
`PollRoundCompleteRevealInputLoop` captures early input timing into
`STATE_TRANSITION`; the staged reveal branches then choose the 500/200/100/50
point bonus score constants or the final tile fill before
`WaitRoundCompleteRevealFramesLoop` gives the update a fixed visible delay.

## Open Questions

- Continue naming the remaining slot-local fields. `+$03` is currently only
  proven as the BGM cursor toggled-frame shadow, while `+$0F` is only proven as
  the Down-held fast-fall clamp byte. Do not broaden either name without a
  second consumer.
- High-bit object type variants `$81-$87` are renderer-supported aliases of
  `$01-$07` with inherited OAM attribute bit `$80`, but the current static
  search found no producer that writes a high-bit logical sprite object type.
- Object type `$07` is currently only proven as a reserved frame-table entry;
  it still needs a confirmed producer before it can receive a broader semantic
  name.
