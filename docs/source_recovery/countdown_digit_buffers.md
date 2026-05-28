# Countdown Digit Buffers

`UpdateCountdownTimer` expands packed BCD score digits into temporary 7-row
bitmap buffers at `$C7AE-$C7CD`. `RandomNext` then copies one buffer pair to
VRAM and doubles every byte horizontally.

| Address | Name | Use |
|---------|------|-----|
| `$C7AE-$C7B5` | `COUNTDOWN_DIGIT_BUFFER_0` | First buffer in the `$9120` blit pair. |
| `$C7B6-$C7BD` | `COUNTDOWN_DIGIT_BUFFER_1` | Second buffer in the `$9120` blit pair. |
| `$C7BE-$C7C5` | `COUNTDOWN_DIGIT_BUFFER_2` | First buffer in the `$9020` blit pair. |
| `$C7C6-$C7CD` | `COUNTDOWN_DIGIT_BUFFER_3` | Second buffer in the `$9020` blit pair. |
| `$C7CE` | `COUNTDOWN_BLIT_TIMER` | Nonzero while pending digit-buffer blits remain; `LoadAnimData` seeds it with `2`, `RandomNext` decrements it. |
| `$C7CF` | `COUNTDOWN_BLIT_PHASE` | Toggled by `UpdateCountdownTimer`; selects whether `RandomNext` blits buffers 2/3 to `$9020` or buffers 0/1 to `$9120`. |

The source digits come from the score BCD accumulator at `SCORE_BCD_LOW`,
`SCORE_BCD_MID`, and `SCORE_BCD_HIGH`. `CountdownDigitPatternTable` provides the
8-byte bitmap for each decimal digit; the update routine combines nibbles from
multiple digit patterns into the four staging buffers before the VRAM blit.
