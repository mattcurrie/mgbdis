# Result Record State

The recovered result record area lives at `$C709-$C75C`.

## Records

| Address | Constant | Evidence |
|---------|----------|----------|
| `$C709-$C729` | `A_TYPE_RESULT_RECORDS` | Three `RESULT_RECORD_SIZE` (`$0B`) records. `RefreshField` initializes the first byte of each record to `$FF`; the result setup path starts `SetupRound` from this base when `GAME_TYPE` is zero. |
| `$C72A-$C74A` | `B_TYPE_RESULT_RECORDS` | Three `RESULT_RECORD_SIZE` records. The same setup path starts from this base when `GAME_TYPE` is nonzero. |
| `$C74B-$C755` | `CURRENT_RESULT_RECORD` | `ClearField` stages the current score digits, sprite animation state/frame, and A/B-specific detail digits here before comparing and inserting the record. |
| `$C756` | `RESULT_RECORDS_INIT_FLAG` | `RefreshField` returns if this byte is nonzero; otherwise it seeds the six record heads and this flag with `$FF`. |
| `$C757-$C75A` | `WRAM_PERSIST_MAGIC` | Startup checks bytes `$C7,$8A,$29,$36`; when they match, WRAM clearing skips from `$C709` to `ROUND_END_WAIT_TIMER`, preserving the result records and magic. |
| `$C75B-$C75C` | `ROUND_END_WAIT_TIMER` | `ProcessNewHighScore` seeds this little-endian timer with `$003C`; the 2P round-end path decrements it before continuing result flow. |

## Record Layout

Each stored record is 11 bytes:

| Offset | Meaning |
|--------|---------|
| `+0..+4` | Five low-nibble score digits copied from `SCORE_DIGITS`. |
| `+5` | `SPRITE_ANIM_STATE`. |
| `+6` | `SPRITE_ANIM_FRAME`. |
| `+7..+9` | A-type egg count digits in hundreds/tens/ones order. |
| `+10` | A-type padding/ignored byte; `SetupRound` skips it after drawing the three egg digits. |
| `+7..+10` | B-type total timer digits copied from `TOTAL_TIMER_DIGITS`. |

`ClearField` masks all 11 staged bytes to low nibbles before comparing them
with existing records through `InitRound`. If the staged record ranks above an
existing entry, the lower records are shifted down and `CURRENT_RESULT_RECORD`
is copied into the selected slot.
