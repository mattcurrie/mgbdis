# Field Animation State

This note documents the recovered WRAM state at `$C6C3-$C6CE`.

## Object Slots

`SetupMultiplayer` updates four logical sprite object slots when their active
flags are nonzero:

| Slot | Active flag | Cursor | Delta table | Update routine | Coordinate effect |
|------|-------------|--------|-------------|----------------|-------------------|
| 11 | `FIELD_ANIM_SLOT_11_ACTIVE` (`$C6C8`) | `FIELD_ANIM_SLOT_11_CURSOR` (`$C6C3`) | `FieldSideDeltaTable` | `UpdateFieldAnimSlot11` | add delta to X and Y |
| 10 | `FIELD_ANIM_SLOT_10_ACTIVE` (`$C6C9`) | `FIELD_ANIM_SLOT_10_CURSOR` (`$C6C4`) | `FieldSideDeltaTable` | `UpdateFieldAnimSlot10` | subtract delta from X, add delta to Y |
| 13 | `FIELD_ANIM_SLOT_13_ACTIVE` (`$C6CA`) | `FIELD_ANIM_SLOT_13_CURSOR` (`$C6C5`) | `FieldRowDeltaTable` | `UpdateFieldAnimSlot13` | add delta to X and Y |
| 12 | `FIELD_ANIM_SLOT_12_ACTIVE` (`$C6C7`) | `FIELD_ANIM_SLOT_12_CURSOR` (`$C6C6`) | `FieldRowDeltaTable` | `UpdateFieldAnimSlot12` | subtract delta from X, add delta to Y |

Each step routine indexes its table with the slot cursor. The table terminator
is `FIELD_ANIM_END_SENTINEL` (`$10`); reaching it clears the slot's active flag,
resets that cursor, clears the logical sprite object's type byte, and returns
the sentinel to the caller.

## Column Timers

`FIELD_COLUMN_TIMERS` (`$C6CB-$C6CE`) is a four-byte timer array. `UpdateBoard`
indexes it with `PIECE_ROTATION` and reloads the selected byte with
`FIELD_COLUMN_TIMER_RELOAD` (`$0A`) after creating the corresponding object in
slot `10 + PIECE_ROTATION`.

`UpdateFieldTimers` walks four entries. When an entry decrements to zero,
`ResetTimers` maps the timer index back to logical sprite object slot `10 + b`
and `UpdateTimerDisplay` clears that 16-byte `$C2xx` object slot.
