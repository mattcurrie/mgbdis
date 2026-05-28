# Egg Counter State

The recovered egg counter state lives at `$C6D2-$C6D5`.

| Address | Name | Evidence |
|---------|------|----------|
| `$C6D2` | `EGG_COUNT_RESERVED` | Cleared with the counter by `StartNextRound`, `InitPlayfield`, `RunTitleMenu`, and `ClearEggCount`; no direct read has been confirmed. |
| `$C6D3` | `EGG_COUNT_ONES` | Incremented first by `IncrementEggCounter`; drawn by `DrawEggCount` as tile `EGG_COUNT_TILE_BASE + digit`. |
| `$C6D4` | `EGG_COUNT_TENS` | Incremented when ones wraps; drawn by `DrawEggCount` as tile `EGG_COUNT_TILE_BASE + digit`. |
| `$C6D5` | `EGG_COUNT_HUNDREDS` | Incremented when tens wraps; copied into result/history records before tens and ones. |
| `$C6E8-$C6EA` | `EGG_TEXT_PULSE_FRAME` / `EGG_TEXT_PULSE_TIMER` / `EGG_TEXT_PULSE_STEPS` | Seeded by `StartEggTextPulse` when the ones digit wraps; `UpdateEggTextAnimation` counts down and alternates `AnimateSprite` frame 1/2 with a `$28` frame delay. |
| `$C6F3-$C6F4` | `EGG_TEXT_ALT_ANIM_ACTIVE` / `EGG_TEXT_ALT_ANIM_PHASE` | `EnableEggTextAltAnimation` sets the active flag when the tens digit wraps; VBlank state checking calls `ToggleEggTextAltAnimation` while playing, toggling `AnimateSprite` frames 1/2. |

`IncrementEggCounter` treats `$C6D3-$C6D5` as a decimal three-digit counter.
Each digit rolls over at `EGG_COUNT_DIGIT_LIMIT` (`10`), and the counter
saturates at `999` through `EGG_COUNT_MAX_DIGIT`.

`DrawEggCount` writes the ones and tens digits into the gameplay display. Result
setup copies the digits in hundreds/tens/ones order into
`CURRENT_RESULT_DETAIL_DIGITS`, which is later compared with previous result
records.

When the ones digit wraps, `StartEggTextPulse` starts a short `AnimateSprite`
frame 1/2 pulse. When the tens digit wraps, `EnableEggTextAltAnimation` enables
the continuous frame 1/2 alternate path driven by the playing-state VBlank
check.

`SPRITE_ANIM_TICK_COUNTER` at `$C6D1` is a separate 10-tick divider used by the
title sprite animation path before calling `AdvanceSpriteAnimFrame`.
