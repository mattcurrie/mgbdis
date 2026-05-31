# Countdown Digit Buffers

`UpdateCountdownTimer` expands packed BCD score digits into temporary 7-row
bitmap buffers at `$C7AE-$C7CD`. `RandomNext` then copies one buffer pair to
VRAM and doubles every byte horizontally.

| Address | Name | Use |
|---------|------|-----|
| `$C7AE-$C7B5` | `COUNTDOWN_DIGIT_BUFFER_0` | First buffer in the `COUNTDOWN_BLIT_DEST_PHASE1` (`$9120`) blit pair. |
| `$C7B6-$C7BD` | `COUNTDOWN_DIGIT_BUFFER_1` | Second buffer in the `COUNTDOWN_BLIT_DEST_PHASE1` (`$9120`) blit pair. |
| `$C7BE-$C7C5` | `COUNTDOWN_DIGIT_BUFFER_2` | First buffer in the `COUNTDOWN_BLIT_DEST_PHASE0` (`$9020`) blit pair. |
| `$C7C6-$C7CD` | `COUNTDOWN_DIGIT_BUFFER_3` | Second buffer in the `COUNTDOWN_BLIT_DEST_PHASE0` (`$9020`) blit pair. |
| `$C7CE` | `COUNTDOWN_BLIT_TIMER` | Nonzero while pending digit-buffer blits remain; `Draw1PCountdownDigitTileSlots` seeds it with `2`, `RandomNext` decrements it. |
| `$C7CF` | `COUNTDOWN_BLIT_PHASE` | Toggled by `UpdateCountdownTimer`; selects whether `RandomNext` blits buffers 2/3 to `COUNTDOWN_BLIT_DEST_PHASE0` or buffers 0/1 to `COUNTDOWN_BLIT_DEST_PHASE1`. |

`Draw1PCountdownDigitTileSlots` chooses
`COUNTDOWN_TILE_SLOT_A_TYPE_COORD` (`$0310`) for A-type and
`COUNTDOWN_TILE_SLOT_B_TYPE_COORD` (`$0210`) for B-type, then writes the four
alternating tile IDs `COUNTDOWN_TILE_SLOT_0..3`. When no blit is pending, it
reloads `COUNTDOWN_BLIT_TIMER` with `COUNTDOWN_BLIT_TIMER_RELOAD` (`2`).

The source digits come from the score BCD accumulator at `SCORE_BCD_LOW`,
`SCORE_BCD_MID`, and `SCORE_BCD_HIGH`. `CountdownDigitPatternTable` provides the
8-byte bitmap for each decimal digit; the update routine combines nibbles from
multiple digit patterns into the four staging buffers before the VRAM blit.
The combine path uses `COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK` and
`COUNTDOWN_PATTERN_LOW_NIBBLE_MASK` while extracting or merging those half-byte
bitmap columns. `COUNTDOWN_BLIT_PHASE_TOGGLE_MASK` flips the phase byte between
the two buffer pairs, and `COUNTDOWN_PHASE1_SPILL_PIXEL_MASK` names the single
pixel carried into buffer 0 during the phase-1 merge.
`Draw1PCountdownDigitTileSlots` places the four alternating countdown tile IDs
in the 1P playfield tilemap and seeds `COUNTDOWN_BLIT_TIMER` when no countdown
VRAM blit is already pending.

`UpdateCountdownTimer` alternates between the phase-0 buffer pair
(`COUNTDOWN_DIGIT_BUFFER_2/3`) and the phase-1 buffer pair
(`COUNTDOWN_DIGIT_BUFFER_0/1`). The recovered local labels now name the
buffer-level operations: phase 0 copies/merges rows through
`CopyCountdownPhase0Buffer2LeftLoop`,
`MergeCountdownPhase0Buffer2RightLoop`, and
`CopyCountdownPhase0Buffer3Loop`; phase 1 uses
`CopyCountdownPhase1Buffer1LeftLoop`,
`MergeCountdownPhase1Buffer1RightLoop`, and
`CopyCountdownPhase1Buffer0Loop`.

`RandomNext` performs the actual doubled-byte VRAM staging. Phase 0 uses
`BlitCountdownPhase0Buffer2Loop` and `BlitCountdownPhase0Buffer3Loop`; phase 1
uses `BlitCountdownPhase1Buffer0Loop` and
`BlitCountdownPhase1Buffer1Loop`.
