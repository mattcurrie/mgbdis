# Field Animation State

This note documents the recovered WRAM state at `$C6C3-$C6CE`.

## Object Slots

`UpdateFieldAnimationSlots` updates four logical sprite object slots when their
active flags are nonzero:

| Slot | Active flag | Cursor | Delta table | Update routine | Coordinate effect |
|------|-------------|--------|-------------|----------------|-------------------|
| 11 | `FIELD_ANIM_SLOT_11_ACTIVE` (`$C6C8`) | `FIELD_ANIM_SLOT_11_CURSOR` (`$C6C3`) | `FieldSideDeltaTable` | `UpdateFieldAnimSlot11` | add delta to X and Y |
| 10 | `FIELD_ANIM_SLOT_10_ACTIVE` (`$C6C9`) | `FIELD_ANIM_SLOT_10_CURSOR` (`$C6C4`) | `FieldSideDeltaTable` | `UpdateFieldAnimSlot10` | subtract delta from X, add delta to Y |
| 13 | `FIELD_ANIM_SLOT_13_ACTIVE` (`$C6CA`) | `FIELD_ANIM_SLOT_13_CURSOR` (`$C6C5`) | `FieldRowDeltaTable` | `UpdateFieldAnimSlot13` | add delta to X and Y |
| 12 | `FIELD_ANIM_SLOT_12_ACTIVE` (`$C6C7`) | `FIELD_ANIM_SLOT_12_CURSOR` (`$C6C6`) | `FieldRowDeltaTable` | `UpdateFieldAnimSlot12` | subtract delta from X, add delta to Y |

Slot 11's second coordinate update is labeled `UpdateFieldAnimSlot11BaseY`;
after the X update succeeds, it applies the next `FieldSideDeltaTable` value to
the same object's base-Y field.

Each step routine indexes its table with the slot cursor. The table terminator
is `FIELD_ANIM_END_SENTINEL` (`$10`); reaching it clears the slot's active flag,
resets that cursor, clears the logical sprite object's type byte, and returns
the sentinel to the caller. The cleanup tails are named `EndFieldAnimSlot10`,
`EndFieldAnimSlot11`, `EndFieldAnimSlot12`, and `EndFieldAnimSlot13`.
The per-step table bytes are now expressed as `FIELD_ANIM_DELTA_POSITIVE`,
`FIELD_ANIM_DELTA_ZERO`, and `FIELD_ANIM_DELTA_NEGATIVE`; the side and row
helpers consume those values as signed/zero coordinate deltas before checking
for the `$10` end sentinel. The source groups the non-terminal bytes as
`FIELD_ANIM_DELTA_PAIR` records because the update routines consume one delta
for X and then the next delta for Y on each active animation tick.

`ProcessRoundComplete` seeds all four active flags with
`FIELD_ANIM_ACTIVE_VALUE` after initializing the four
`SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE` slots.

## Column Timers

`FIELD_COLUMN_TIMERS` (`$C6CB-$C6CE`) is a four-byte timer array.
`SpawnFieldColumnEffect` indexes it with `FALLING_PIECE_GRID_COLUMN` and reloads the
selected byte with `FIELD_COLUMN_TIMER_RELOAD` (`$0A`) after creating
`SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT` in logical sprite slot
`FIELD_COLUMN_EFFECT_SLOT_BASE + FALLING_PIECE_GRID_COLUMN`. The caller supplies
`FIELD_COLUMN_EFFECT_FRAME_COMMIT` after `CommitFallingPieceToBoard` and
`FIELD_COLUMN_EFFECT_FRAME_LAND` after the landing-only path.

`UpdateFieldTimers` walks four entries. When an entry decrements to zero,
`ClearExpiredFieldColumnEffect` maps the timer index back to logical sprite
object slot `FIELD_COLUMN_EFFECT_SLOT_BASE + b`, and `ClearSpriteObjectSlot`
clears that 16-byte `$C2xx` object slot through
`ClearSpriteObjectSlotLoop`.
