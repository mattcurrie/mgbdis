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

## Logical Object Slot Format

Each slot is `$10` bytes. `InitSpriteBuffer` clears the first byte of every
slot; a zero type disables the object.

| Offset | Meaning | Evidence |
|--------|---------|----------|
| `+$00` | Object type / high-bit attribute source | Read first. If zero, the slot is skipped. The same byte is decremented and used to index `SpriteUpdatePointerTable`; bit `$80` is also saved for possible attribute inheritance. |
| `+$02` | Animation frame index | If `$FF`, the slot is skipped. Otherwise multiplied by 4 and used to pick a frame record from the selected frame table. |
| `+$04` | Base Y | Added to each layout Y delta plus OAM bias `$10`. |
| `+$06` | Base X | Added to each layout X delta plus OAM bias `$08`. |

The remaining slot bytes are used by producers elsewhere and still need a
dedicated trace.

## Sprite Update Table Format

`SpriteUpdatePointerTable` is indexed by `object_type - 1` and returns a frame
table pointer. `UpdateSprites` does not mask off bit `$80` before indexing, so
high-bit object types may intentionally select alternate entries while also
supplying an inherited attribute bit.

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

- Producers for the remaining bytes in each `$C2x0` logical slot still need to
  be traced and named.
- The exact set of high-bit object types, if any, needs runtime/call-site
  confirmation because the high bit is not masked before the frame-table index.
- The frame tables are now structurally understood, but the individual object
  types still need semantic names.
