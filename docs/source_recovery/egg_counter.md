# Egg Counter State

The recovered egg counter state lives at `$C6D2-$C6D5`.

| Address | Name | Evidence |
|---------|------|----------|
| `$C6D2` | `EGG_COUNT_RESERVED` | Cleared with the counter by `StartNextRound`, `InitPlayfield`, `RunTitleMenu`, and `ClearEggCount`; no direct read has been confirmed. |
| `$C6D3` | `EGG_COUNT_ONES` | Incremented first by `IncrementEggCounter`; drawn by `DrawEggCount` as tile `EGG_COUNT_TILE_BASE + digit`. |
| `$C6D4` | `EGG_COUNT_TENS` | Incremented when ones wraps; drawn by `DrawEggCount` as tile `EGG_COUNT_TILE_BASE + digit`. |
| `$C6D5` | `EGG_COUNT_HUNDREDS` | Incremented when tens wraps; copied into result/history records before tens and ones. |

`IncrementEggCounter` treats `$C6D3-$C6D5` as a decimal three-digit counter.
Each digit rolls over at `EGG_COUNT_DIGIT_LIMIT` (`10`), and the counter
saturates at `999` through `EGG_COUNT_MAX_DIGIT`.

`DrawEggCount` writes the ones and tens digits into the gameplay display. Result
setup copies the digits in hundreds/tens/ones order into the record buffer at
`$C752-$C754`, which is later compared with previous result records.

`SPRITE_ANIM_TICK_COUNTER` at `$C6D1` is a separate 10-tick divider used by the
title sprite animation path before calling `AdvanceSpriteAnimFrame`.
