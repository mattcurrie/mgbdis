# Sprite / OAM Recovery Notes

This document records the current evidence for the logical sprite object buffer,
shadow OAM, and Bank 1 sprite update tables.

## Runtime Buffers

| Range | Name | Confidence | Evidence |
|-------|------|------------|----------|
| `$C200-$C2FF` | `SPRITE_OBJECTS` | High | `UpdateSprites` scans 16 slots by loading `D=$C2`, adding `$10` to the low byte each iteration, and stopping when the low byte wraps to `$00`. |
| `$C400-$C49F` | `SHADOW_OAM` | High | `ClearOAM` clears `$A0` bytes; the HRAM OAM DMA routine copies page `$C4` to hardware OAM. |
| `$FF8E` | `SPRITE_SCAN_SLOT_OFFSET` | High | Temporary slot offset while `UpdateSprites` scans `$C200`, `$C210`, ..., `$C2F0`. |
| `$FF8F` | `SHADOW_OAM_WRITE_OFFSET` | High | Temporary OAM write offset while `UpdateSprites` appends expanded hardware sprite entries. |
| `$FF90/$FF91` | `SPRITE_BASE_X_TMP` / `SPRITE_BASE_Y_TMP` | High | Per-object base position loaded from object slot offsets `$06` and `$04`; `UpdateSprites` adds the Game Boy OAM hardware biases `$08/$10`. |
| `$FF92` | `SPRITE_OBJECT_ATTR_TMP` | Medium | Stores object type bit `$80`, later ORed into per-sprite attributes when the layout attribute byte has bit 1 set. |
| `$FF96` | `SPRITE_OBJECT_SLOT_OFFSET_TMP` | High | `UpdateSpriteObject` stores the selected `$C2xx` slot offset before copying the staged object back. |
| `$C68B` | `SPRITE_OBJECT_STAGING_INDEX` | High | `UpdateSpriteObject` saves its input index here; `MovePieceDown` uses it to clear the same gameplay object slot. |
| `$C68C-$C695` | `SPRITE_OBJECT_STAGING` | High | `UpdateSpriteObject` copies 10 bytes from one `$C2xx` slot into this work area, updates movement/state fields, then copies the 10-byte record back. |

## Logical Object Slot Format

Each slot is `$10` bytes. `InitSpriteBuffer` clears the first byte of every
slot; a zero type disables the object.

| Offset | Meaning | Evidence |
|--------|---------|----------|
| `+$00` | Object type / high-bit attribute source | Read first. If zero, the slot is skipped. The same byte is decremented and used to index `SpriteUpdatePointerTable`; bit `$80` is also saved for possible attribute inheritance. |
| `+$02` | Animation frame index | If `$FF`, the slot is skipped. Otherwise multiplied by 4 and used to pick a frame record from the selected frame table. |
| `+$04` | Base Y | Added to each layout Y delta plus OAM bias `$10`. |
| `+$06` | Base X | Added to each layout X delta plus OAM bias `$08`. |
| `+$07` | Delay counter | `UpdateSpriteObject` decrements this field while `SPRITE_OBJECT_PHASE` is `$01`; when it reaches zero, the routine reloads it from `$C66E` and advances the phase to `$02`. |
| `+$08` | Object phase | `0` disables the producer-side update, `$01` waits on `SPRITE_OBJECT_DELAY_COUNTER`, and `$02` enters `UpdateMatchState`; `CheckMatch` tests slots 1-4 for phase `$02` before clamping the drop timers. |
| `+$09` | Tile / piece payload | In the staged `$C695` byte, `UpdateMatchState` passes this value to `DrawGridPiece`, writes it back into `BOARD_DATA`, and compares `$07/$08` for scan/landing behavior. `AnimateGameOver` also writes this byte as the visible piece payload. |

The remaining slot bytes, including `+$01`, `+$03`, `+$05`, and `+$0F`, are
used by producers elsewhere and still need a dedicated trace.

## Object Producers

`UpdateSpriteObject` is the first confirmed producer-side bridge for gameplay
object slots. Its input `A` selects slots `$C210`, `$C220`, `$C230`, and
`$C240` by computing `(A + 1) * $10`. The routine copies 10 bytes from that
slot into `SPRITE_OBJECT_STAGING`, updates state through `UpdateMatchState` or
the slot-local `SPRITE_OBJECT_DELAY_COUNTER`, then copies the same 10-byte
record back to the selected slot. `MovePieceDown` uses the saved index to clear
the selected 10-byte record when the object finishes. The staged tail bytes are
now named as offsets: `SPRITE_OBJECT_DELAY_COUNTER` (`+$07`),
`SPRITE_OBJECT_PHASE` (`+$08`), and `SPRITE_OBJECT_TILE_ID` (`+$09`, address
`$C695` while staged).

Confirmed slot groups:

| Slot/range | Current evidence |
|------------|------------------|
| Slot 0 (`$C200`) | `ProcessColumn` initializes `SPRITE_OBJECT_TYPE_PLAYER_CURSOR`, frame `$00`, base Y `$80`, and base X `$20`. `InitGameState2` advances its frame, and left/right input adjusts base X by `$20`. |
| Slots 1-4 (`$C210-$C24F`) | `DrawBox` calls `UpdateSpriteObject` four times. Collision/drop code scans these four slots and uses additional bytes such as `+$05`, `+$08`, and `+$0F` for gameplay state. |
| Slots 5-8 (`$C250-$C28F`) | Menu/title helpers clear or scan this range; individual byte meanings still need trace. |
| Slots 9-13 (`$C290-$C2DF`) | Options cursors, round-complete animations, countdown digits, and 2P field transition objects use these slots. |

Confirmed object types:

| Type | Constant | Evidence |
|------|----------|----------|
| `$01` | `SPRITE_OBJECT_TYPE_PLAYER_CURSOR` | Slot 0 setup and left/right input path. |
| `$02` | `SPRITE_OBJECT_TYPE_GAME_OVER_PIECE` | Written by `AnimateGameOver` into slots selected from game-over state. |
| `$03` | `SPRITE_OBJECT_TYPE_ROUND_TRANSITION` | Written to slot 9 during the round-complete / 2P transition path. |
| `$04` | `SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE` | Written to slots 10-13 by `ProcessRoundComplete` and the 2P round-complete path. |
| `$05` | `SPRITE_OBJECT_TYPE_SETTINGS_CURSOR` | Used by `SettingsCursorSpriteInit0` through `SettingsCursorSpriteInit2`. |

## Sprite Update Table Format

`SpriteUpdatePointerTable` is indexed by `object_type - 1` and returns a frame
table pointer. `UpdateSprites` does not mask off bit `$80` before indexing, so
high-bit object types may intentionally select alternate entries while also
supplying an inherited attribute bit.

In source, the formerly flat `01:$40A0-$42F4` payload is split into:

| Label family | Meaning |
|--------------|---------|
| `SpriteFrameTable_*` | Per-object animation frame records. High-confidence object types now use semantic suffixes; unknown types still use `Object6`/`Object7`. |
| `SpriteTileList_*` | Tile IDs read sequentially, one byte for each emitted hardware sprite. |
| `SpriteLayout_*` | Repeated `y_delta, x_delta, attr` triples. |

Each frame table entry is 4 bytes:

```text
dw tile_id_list
dw layout_list
```

`tile_id_list` is read one byte per emitted hardware sprite. `layout_list` is
read as repeated triples:

```text
db y_delta, x_delta, attr
```

The emitted hardware OAM entry is:

```text
Y    = object_base_y + $10 + y_delta
X    = object_base_x + $08 + x_delta
Tile = *tile_id_list++
Attr = attr, optionally ORed with the saved object `$80` bit when `attr` bit 1 is set
```

`attr` bit 0 terminates the layout list after the current hardware sprite has
been emitted. This makes bit 0 a local end marker as well as part of the final
OAM attribute byte.

Some labels intentionally overlap because the original data reuses subranges.
For example, `SpriteLayout_4205` starts inside `SpriteLayout_41fc`, and
`SpriteTileList_42bf` shares its address with `SpriteLayout_42bf`.

## Redraw Gate

`LCD_REDRAW` controls `UpdateSprites`:

| Value before `UpdateSprites` | Behavior |
|------------------------------|----------|
| `$01` | Expand logical object slots into shadow OAM. |
| `$00` | Set `LCD_REDRAW` to `$FF` and hide all sprites. |
| Other | Return without changing OAM. |

After expanding active logical objects, unused shadow OAM entries are hidden by
writing Y=`$A0` until offset `$98`. The direct "full hide" routine writes
Y=`$A0` for all 40 hardware sprites.

## Open Questions

- The producer path for gameplay slots 1-4 is now traced, but the exact
  semantics of slot-local bytes `+$01`, `+$03`, `+$05`, `+$07`, `+$08`,
  `+$09`, and `+$0F` still need narrower names.
- The exact set of high-bit object types, if any, needs runtime/call-site
  confirmation because the high bit is not masked before the frame-table index.
- Object types `$06` and `$07` still need semantic names.
