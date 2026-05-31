# Bank 1 Sound/Music Engine Notes

This document records the current recovered model of the Bank 1 sound sequence
interpreter. Names are conservative until the command format is fully decoded.

## Confirmed Entry Points

| Address | Label | Role |
|---------|-------|------|
| `01:$53CF` | `SoundEngine` | Public sound/BGM command entry. Handles stop/reset cases, then selects a sound table entry. |
| `01:$53F7` | `SoundLookupIndex` | Converts a sound index into a three-byte table entry under `$7C2C`. |
| `01:$55E2` | `StartSoundSequence` | Expands the selected sound entry into per-channel sequence pointers and active sound IDs. |
| `01:$4C91` | `UpdateSoundChannels` | VBlank-time scan over the eight active sound channels, with pause gating for channels 0-3. |
| `01:$4CC6` | `TickSoundChannel` | Per-channel note-length, duty-rotate, pitch-slide, delay, and vibrato update path. |
| `01:$4D4E` | `SoundSequenceStep` | Per-channel sequence tick; reloads delay and dispatches command parsing. |
| `01:$4D65` | `CountdownSequence` | Reads sequence bytes and executes commands until a note/delay/end condition stops the tick. |

## Sound Index Table

`SoundLookupIndex` and `StartSoundSequence` use `index * 3 + $7C2C`.
The recovered table covers sound indexes `$00-$72`.

| Range | Label | Format |
|-------|-------|--------|
| `01:$7C2C-$7D84` | `SoundIndexTable`, `SoundIndexEntry_*` | `SOUND_INDEX_ENTRY flags, sequence_pointer` |

The first byte packs channel/priority information used by
`ExpandSoundIndexChannelEntryLoop` and `StartSoundSequence`. The pointer can
target either the main stream at `$569A-$7C01` or short sound effects in the
tail region at `$7D85-$7FFE`.
The high bits (`SOUND_INDEX_ENTRY_COUNT_BITS`, `$C0`) encode how many adjacent
table entries are part of the same sound start, and the low nibble
(`SOUND_INDEX_ENTRY_CHANNEL_MASK`, `$0F`) selects the channel slot for each
entry. For example, `SND_TITLE_BGM` starts at `$30` and expands through the
adjacent `$31-$33` channel entries; those adjacent numeric labels are table
continuations rather than independently proven public `PlaySound` IDs.
The table source now uses `SOUND_INDEX_ENTRY` records and expresses the flags
byte with
`SOUND_INDEX_ENTRY_COUNT_1..4` and `SOUND_INDEX_ENTRY_CHANNEL_0..7` constants;
the count constants name the total adjacent entries started by the first table
entry. Entry `$00` is represented with
`SOUND_INDEX_ENTRY_SENTINEL_FLAGS` / `SOUND_INDEX_ENTRY_SENTINEL_POINTER`; it
remains scoped as sentinel data because no live command path is confirmed to
use it as a playable sound ID.

`StartSoundSequence` now has local names for the channel-entry expansion path:
`FindSoundSequencePointerSlot`, `InstallSoundSequenceChannelEntry`,
`StoreSoundSequencePointerForChannel`, `CheckSoundCommandForBgmActiveState`,
`StoreSoundBgmActiveState`, and `ReturnFromStartSoundSequence`. The symbol file
also now records the recovered code/data boundaries around `$55E2-$7FFF`
instead of treating the full `$55E2-$5FE2` setup/sequence region as one data
blob.

The entry at `$569A` is important: it proves the pitch table ends at `$5699`.
`$569A` starts a real sequence (`$ED,$00,...`) even though it was previously
included as the last word of `SoundPitchBaseTable`.

`SoundIndexEntry_TitleBgm` starts a four-channel entry at channel 0, so its
direct sequence targets are now named
`TitleBgmChannel0Sequence` through `TitleBgmChannel3Sequence`. This is limited
to the top-level `SND_TITLE_BGM` entry points at `01:$569A`, `$5764`, `$580B`,
and `$5A6F`; internal `$FD/$FE` joins inside the command stream keep
address-based labels until the music command roles are decoded.

`TitleBgmChannel1Sequence` now exposes its setup commands as generic sound
records: one `$EC` duty/length command, one `$EA` vibrato command, three
`$D0-$DF` length/envelope commands, and five `$E0-$EF` octave commands. The
remaining note bytes in that top-level stream stay raw until their pitch and
duration roles are decoded.

`TitleBgmChannel2Sequence` now exposes its top-level setup as command records:
one `$D6,$12` length/envelope command followed by four `$FD` sub-sequence calls
to `SoundSequenceData_5a34`. The shared `SOUND_SUBSEQUENCE_CALL` macro is kept
generic because the parser treats `$FD` as a returnable sub-sequence call across
music and effect streams.

`TitleBgmChannel3Sequence` and its `SoundSequenceData_5a89` loop now expose the
channel-3 command form: one-byte `$D0-$DF` length-scale setup, `$C0-$CF` rest
notes, `$B0-$BF` nested-sound note commands with their one-byte sound operand,
and the final `$FE` unconditional loop back to `SoundSequenceData_5a89`.

The same direct-target naming is now applied to the option and preview BGMs:
`BgmOption0Channel0Sequence` through `BgmOption2Channel3Sequence` and
`BgmPreview0Channel0Sequence` through `BgmPreview2Channel3Sequence` identify
only the top-level channel streams installed by `SoundIndexEntry_BgmOption*`
and `SoundIndexEntry_BgmPreview*`.

The `BgmOption0*` through `BgmOption2*` and `BgmPreview0*` through
`BgmPreview2*` channel entry heads now expose their setup and short top-level
command records. Channel 0 uses tempo, master-volume, duty/length,
frequency-carry toggle, length/envelope, rest-note, vibrato, and octave records
where present; channel 1 uses duty/length, length/envelope, vibrato, and octave
records where present; channel 2 uses length/envelope, vibrato, rest-note, and
octave records where present; channel 3 uses the one-byte channel-3
length-scale form plus rest-note and visual-update records.

The BGM preview channel-3 phrase labels now expose the same parser-confirmed
shape for the menu visual pulse streams: `MusicSequenceData_60ce` through
`MusicSequenceData_6158`, `MusicSequenceData_64f0` through
`MusicSequenceData_656e`, and `MusicSequenceData_6b2a` through
`MusicSequenceData_6c9b` use `SOUND_VISUAL_UPDATE`, `SOUND_REST_NOTE`,
`SOUND_CHANNEL3_LENGTH_SCALE`, and `SOUND_LOOP_JUMP` records where present.
These records describe the command stream only; they do not assign musical note
names.

`SoundIndexEntry_LinkMaster` and `SoundIndexEntry_LinkSlave` now expose their
top-level channel streams too. Both entries share
`LinkRoleSharedChannel0Sequence`; channels 1-3 split into
`LinkMasterChannel*Sequence` and `LinkSlaveChannel*Sequence`.
The link-role entry heads now expose the parser-confirmed setup and branch
records: tempo, master-volume, duty/length, vibrato, frequency-carry,
length/envelope, octave, rest-note, `$FD` sub-sequence calls, and `$FE` loop
jumps. `LinkSlaveChannel3Sequence` keeps the existing `MusicSequenceData_71e4`
boundary by splitting that one `$FD` pointer into explicit `LOW` / `HIGH`
bytes.
`SoundIndexEntry_Confirm`, `SoundIndexEntry_LinkResultNonzero`,
`SoundIndexEntry_LinkResultZero`, `SoundIndexEntry_LinkResultConfirmWait`, and
`SoundIndexEntry_LinkResultMenuWait` similarly use direct channel-entry labels
for their top-level streams. These names are entry-point names only; internal
music-stream joins keep address-based labels.

`ConfirmChannel0..3Sequence` now expose their parser-confirmed command records:
tempo, master-volume, duty/length, vibrato, frequency-carry, length/envelope,
octave, rest-note, pitch-slide, channel-3 length-scale, channel-3 nested sound
notes, and sequence ends. Pitch/duration bytes remain raw until note naming has
independent evidence.

`LinkResultNonzeroChannel0..2Sequence` and
`LinkResultZeroChannel0..2Sequence` now expose their parser-confirmed setup,
octave, rest-note, vibrato, frequency-carry, length/envelope, and sequence-end
records. These are the short terminal-result fanfare streams selected by
`SoundIndexEntry_LinkResultNonzero` and `SoundIndexEntry_LinkResultZero`; the
raw pitch/duration bytes remain unnamed.

`LinkResultConfirmWaitChannel0..3Sequence` and
`LinkResultMenuWaitChannel0..3Sequence` now expose their setup records and the
short `$FD` / `$FE` branch structure in the associated loop streams. The shared
confirm/menu wait phrase labels now also expose high-confidence octave,
rest-note, channel-3 nested-sound-note, loop, and sequence-end records, while
the remaining pitch/duration bytes stay raw until note naming has independent
support. The remaining inline channel-2 phrases in the confirm/menu wait
streams now expose octave and rest-note command bytes, and the menu-wait
channel-1 inline phrase exposes its octave command byte.

The remaining named result/preplay sound entries now follow the same convention:
`SoundIndexEntry_Result1PNoRank`, `SoundIndexEntry_Result1PRanked`,
`SoundIndexEntry_TwoPlayerPreplayMasterInit`,
`SoundIndexEntry_TwoPlayerPreplaySlaveInit`,
`SoundIndexEntry_Result2PNonzeroRank`, and `SoundIndexEntry_Result2PZeroRank`
point to `Result*Channel*Sequence` and
`TwoPlayerPreplay*InitChannel*Sequence` labels for their top-level channel
streams.

The single-player result channel entry heads also expose their setup and short
top-level command records. `Result1PNoRankChannel*Sequence` and
`Result1PRankedChannel*Sequence` now use generic tempo, master-volume,
duty/length, frequency-carry, vibrato, length/envelope, octave, rest-note, and
sequence-end records where present. The note bytes stay raw until pitch and
duration names are independently decoded.

The two-player result channel entry heads follow the same pattern:
`Result2PNonzeroRankChannel*Sequence` and `Result2PZeroRankChannel*Sequence`
now expose their tempo, master-volume, duty/length, frequency-carry,
length/envelope, octave, rest-note, pitch-slide, and sequence-end command
records while leaving undecoded note bytes raw.

The 2P preplay-init channel entry heads also expose their setup commands with
generic records: `SOUND_TEMPO`, `SOUND_MASTER_VOLUME`, `SOUND_DUTY_LENGTH`,
`SOUND_LENGTH_ENVELOPE`, `SOUND_REST_NOTE`, and
`SOUND_FREQ_CARRY_TOGGLE`. These records describe the parser command shape
without naming the pitches. The four following phrase labels
`MusicSequenceData_7965`, `MusicSequenceData_79c3`, `MusicSequenceData_7a2b`,
and `MusicSequenceData_7a8c` now expose their length/envelope, octave, and loop
command records while leaving pitch/duration bytes raw.

`MusicSequenceData_7bdf`, the channel-4 stream for
`SoundIndexEntry_LinkFieldRise`, now exposes its gate-flag, duty/length,
length/envelope, octave, extended-note, pitch-slide, and sequence-end records
while leaving undecoded note bytes raw.

## Confirmed Sound IDs

These names are based on direct `PlaySound` call sites. Numeric
`SoundIndexEntry_*` labels remain in the table; the source also adds alias
labels for the confirmed entries.

| ID | Constant | Sound table alias | Evidence |
|----|----------|-------------------|----------|
| `$11` | `SND_LINK_FIELD_RISE` | `SoundIndexEntry_LinkFieldRise` | Played by `PlayPendingFieldRiseSound` after a pending 2P field-rise packet is consumed and the new `SCREEN_STATE` value is chosen. |
| `$12` | `SND_ROUND_COMPLETE_REVEAL` | `SoundIndexEntry_RoundCompleteReveal` | Used by the default round-complete transition sound and by the 200/100/50-point A-type round-complete bonus reveal stages. |
| `$16` | `SND_ROUND_COMPLETE_MAJOR_REVEAL` | `SoundIndexEntry_RoundCompleteMajorReveal` | Used when the round transition frame reaches `ROUND_TRANSITION_MAJOR_REVEAL_FRAME`, and by the 500-point A-type round-complete bonus reveal stage. |
| `$1B` | `SND_DROP_START` | `SoundIndexEntry_DropStart` | Called immediately before `StartDropColumnSwapAnimation` when a down/drop input starts the drop animation. |
| `$1C` | `SND_PLACE_PIECE` | `SoundIndexEntry_PlacePiece` | Called by `DrawLandedPieceAndUpdateColumnTop` when a falling piece is drawn into the selected column and the column top row is lowered. |
| `$1E-$25` | `SND_BOARD_SCAN_STEP_MIN` through `SND_BOARD_SCAN_STEP_BASE` | `SoundIndexEntry_BoardScanStep7` through `SoundIndexEntry_BoardScanStep0` | `RunBoardScanTriggerSequence` plays `SND_BOARD_SCAN_STEP_BASE - c` while its scan animation step counter advances from `0` up to `BOARD_SCAN_STEP_MAX` (`7`). |
| `$26` | `SND_COMMIT_PIECE` | `SoundIndexEntry_CommitPiece` | Called by `CommitFallingPieceToBoard`, the code path that writes the falling piece into the board state. |
| `$27` | `SND_PIECE_LAND` | `SoundIndexEntry_PieceLand` | Called by `FinishBoardScanNoTargetLanding` when a board-scan trigger finds no target row, after spawning the landing field-column effect and clearing the current gameplay object. |
| `$28` | `SND_CURSOR_MOVE` | `SoundIndexEntry_CursorMove` | Used by menu cursor movement and simple left/right movement feedback. |
| `$29` | `SND_MATCHING_OAM_SLIDE` | `SoundIndexEntry_MatchingOamSlide` | Played in `ProcessMatching` just before the matching OAM pair starts sliding. |
| `$2B` | `SND_MATCHING_INTRO_BLINK` | `SoundIndexEntry_MatchingIntroBlink` | Played when the matching intro blink frame counter reaches its reset threshold. |
| `$2C` | `SND_MATCHING_RESULT_PANEL_BLINK` | `SoundIndexEntry_MatchingResultPanelBlink` | Played when the result-panel blink frame counter reaches its reset threshold. |
| `$2D` | `SND_ROUND_COMPLETE` | `SoundIndexEntry_RoundComplete` | Called by `ProcessRoundComplete`, including the matching 2P completion path. |
| `$2E` | `SND_PAUSE` | `SoundIndexEntry_Pause` | Called by `PauseGame`. |
| `$30` | `SND_TITLE_BGM` | `SoundIndexEntry_TitleBgm` | Called during title initialization. |
| `$34` | `SND_BGM_OPTION0` | `SoundIndexEntry_BgmOption0` | Stored in `BGM_INDEX` when `OPTION_BGM=0`. |
| `$38` | `SND_BGM_PREVIEW0` | `SoundIndexEntry_BgmPreview0` | Preview sound for `OPTION_BGM=0`. |
| `$3C` | `SND_BGM_OPTION1` | `SoundIndexEntry_BgmOption1` | Stored in `BGM_INDEX` when `OPTION_BGM=1`. |
| `$40` | `SND_BGM_PREVIEW1` | `SoundIndexEntry_BgmPreview1` | Preview sound for `OPTION_BGM=1`. |
| `$44` | `SND_BGM_OPTION2` | `SoundIndexEntry_BgmOption2` | Stored in `BGM_INDEX` when `OPTION_BGM=2`. |
| `$48` | `SND_BGM_PREVIEW2` | `SoundIndexEntry_BgmPreview2` | Preview sound for `OPTION_BGM=2`. |
| `$4C` | `SND_LINK_MASTER` | `SoundIndexEntry_LinkMaster` | Selected in 2P settings when `LINK_ROLE=1`. |
| `$50` | `SND_LINK_SLAVE` | `SoundIndexEntry_LinkSlave` | Selected in 2P settings when `LINK_ROLE!=1`. |
| `$54` | `SND_CONFIRM` | `SoundIndexEntry_Confirm` | Called by `DrawLinkResultConfirmPanelsAndWait`, the matching result finalization path, and start/ready transitions. |
| `$58` | `SND_LINK_RESULT_NONZERO` | `SoundIndexEntry_LinkResultNonzero` | Played by the terminal 2P result screen when `ANIM_FRAME` is nonzero before the result layout is drawn. |
| `$5B` | `SND_LINK_RESULT_ZERO` | `SoundIndexEntry_LinkResultZero` | Played by the terminal 2P result screen when `ANIM_FRAME` is zero; `WaitTerminalLinkResultMenuConfirm` also treats it as an already-active result/menu sound. |
| `$5E` | `SND_LINK_RESULT_CONFIRM_WAIT` | `SoundIndexEntry_LinkResultConfirmWait` | Started by `WaitLinkStartConfirm` unless the nonzero terminal result sound is still active. |
| `$62` | `SND_LINK_RESULT_MENU_WAIT` | `SoundIndexEntry_LinkResultMenuWait` | Started by `WaitTerminalLinkResultMenuConfirm` unless the zero-result sound is still active. |
| `$66` | `SND_RESULT_1P_NO_RANK` | `SoundIndexEntry_Result1PNoRank` | Played by the single-player `ProcessRoundResultAndEnterRoundEnd` path when `RESULT_RANK_POSITION` is zero after stopping active sound. |
| `$69` | `SND_RESULT_1P_RANKED` | `SoundIndexEntry_Result1PRanked` | Played by the single-player `ProcessRoundResultAndEnterRoundEnd` path when `RESULT_RANK_POSITION` is nonzero, before `DrawScoreRanking`. |
| `$6B` | `SND_2P_PREPLAY_MASTER_INIT` | `SoundIndexEntry_TwoPlayerPreplayMasterInit` | Played by `InitTwoPlayerPreplayScreen` when `LINK_ROLE` is not `LINK_ROLE_SLAVE`, before drawing the 2P pre-play screen. |
| `$6D` | `SND_2P_PREPLAY_SLAVE_INIT` | `SoundIndexEntry_TwoPlayerPreplaySlaveInit` | Played by `InitTwoPlayerPreplayScreen` when `LINK_ROLE` is `LINK_ROLE_SLAVE`, before drawing the 2P pre-play screen. |
| `$6F` | `SND_RESULT_2P_NONZERO_RANK` | `SoundIndexEntry_Result2PNonzeroRank` | Played by the two-player `ProcessRoundResultAndEnterRoundEnd` path when the computed rank/result byte is nonzero. |
| `$71` | `SND_RESULT_2P_ZERO_RANK` | `SoundIndexEntry_Result2PZeroRank` | Played by the two-player `ProcessRoundResultAndEnterRoundEnd` path when the computed rank/result byte is zero. |
| `$FF` | `SND_STOP_ALL` / `SND_BGM_OFF` | n/a | Stop command; also stored as the BGM-off sentinel. |

Current direct-call audit: every constant or computed ID loaded immediately
before `PlaySound` in Bank 0/1 is represented by the table above. A follow-up
scan for sequence-internal `$EF` nested-sound commands did not identify another
confirmed producer; the visible `$EF` byte in the sound data is the low byte of
the `$FE` loop target `$6BEF`. The remaining numeric `SoundIndexEntry_XX`
labels are therefore left numeric unless later runtime/player evidence proves a
player-visible role.

## Core State Arrays

The channel index is in `C`. `SOUND_CHANNEL_COUNT` is eight, and channels below
`SOUND_PRIMARY_CHANNEL_COUNT` (`4`) are the primary hardware-facing channels.
Most arrays are indexed by `C`; pointer arrays use
`C * SOUND_SEQUENCE_PTR_BYTES_PER_CHANNEL`.

| Range | Constant | Confidence | Meaning |
|-------|----------|------------|---------|
| `$C000` | `SOUND_STATUS` | Low | Cleared by sound reset; no direct read confirmed yet. |
| `$C001` | `SOUND_COMMAND_ID` | High | Last sound command/index passed to `SoundEngine`; used for priority checks and table lookup. |
| `$C002` | `SOUND_PAUSE_FLAG` | High | Set to `SOUND_PAUSE_FLAG_ACTIVE` by `PauseGame`, cleared by `UnpauseGame`; also gates link/sound updates and uses `SOUND_PAUSE_MUTE_APPLIED_BIT` after pause muting is applied. |
| `$C003` | `SOUND_DEFERRED_ID` | Medium | Deferred/nested sound ID state used around `$EF` nested sound starts and channel 6 sequence end. |
| `$C004` | `SOUND_OUTPUT_MASK` | High | Channel enable mask written by `$EE` and combined with `rNR51`. |
| `$C005` | `SOUND_NR50_BACKUP` | High | Saved `rNR50` value restored after low-index music/SFX priority handling. |
| `$C006-$C015` | `SOUND_CH_SEQUENCE_PTRS` | High | Current sequence pointer per channel, low/high pairs. `SoundUpdate2` reads and advances this pointer. |
| `$C016-$C025` | `SOUND_CH_RETURN_PTRS` | High | Saved return pointer for `$FD` sub-sequence calls. |
| `$C026-$C02D` | `SOUND_CH_ACTIVE_ID` | High | Active sound/priority ID per channel. Cleared when a sequence ends. |
| `$C02A-$C02D` | `SOUND_BGM_ACTIVE_ID` | Medium | Four-byte music priority gate set for low sound IDs below `SOUND_BGM_ACTIVE_ID_GATE`. This overlaps the last four active-ID entries. |
| `$C02E-$C035` | `SOUND_CH_FLAGS` | Medium | Per-channel flags. Observed bits now have named constants for frequency carry, `$FD` return pending, note-output gate, vibrato subtract phase, pitch-slide active/descending state, and duty-rotate active state. |
| `$C036-$C03D` | `SOUND_CH_GATE_FLAGS` | Medium | Secondary per-channel flags; `SOUND_CH_GATE_SUPPRESS_BIT` suppresses selected note/gate writes. |
| `$C03E-$C045` | `SOUND_CH_DUTY_LENGTH` | Medium | Cached NRx1 duty/length bits used before hardware register writes. |
| `$C046-$C04D` | `SOUND_CH_DUTY_ROTATE` | Medium | Rotating duty bits loaded by `$FC` and advanced by `SoundUpdate1`. |
| `$C04E-$C055` | `SOUND_CH_DELAY` | High | Current delay counter per channel. |
| `$C056-$C05D` | `SOUND_CH_VIBRATO_DEPTH` | Medium | Packed vibrato up/down depth loaded by `$EA`. |
| `$C05E-$C065` | `SOUND_CH_VIBRATO_PHASE` | Medium | Packed vibrato reload/counter nibble loaded by `$EA`. |
| `$C066-$C06D` | `SOUND_CH_FREQ_LO_BASE` | Medium | Base low-frequency byte used by vibrato before writing NRx3. |
| `$C06E-$C075` | `SOUND_CH_DELAY_RELOAD` | High | Delay reload value per channel. |
| `$C076-$C0B5` | `SOUND_CH_SLIDE_*`, `SOUND_CH_FREQ_*`, `SOUND_CH_SLIDE_TARGET_*` | Medium | Pitch-slide state loaded by `$EB`, initialized for notes by `InitSoundPitchSlideForNote`, and maintained by `UpdateSoundPitchSlide`. |
| `$C0B6-$C0BD` | `SOUND_CH_NOTE_LENGTH` | Medium | Computed note length / NRx1 length source used by `ProcessSoundNoteCommand` and `WriteSoundChannelLengthRegister`. |
| `$C0BE-$C0C5` | `SOUND_CH_LOOP_COUNTER` | High | `$FE` loop counter per channel. |
| `$C0C6-$C0CD` | `SOUND_CH_LENGTH_SCALE` | Medium | Per-channel length scale loaded by `$D0-$DF`. |
| `$C0CE-$C0D5` | `SOUND_CH_TEMPO_ACCUM` | Medium | Per-channel fractional accumulator used when multiplying note length by tempo. |
| `$C0D6-$C0DD` | `SOUND_CH_OCTAVE` | Medium | Pitch table shift count loaded by `$E0-$EF` low nibble. |
| `$C0DE-$C0E5` | `SOUND_CH_ENVELOPE` | Medium | Cached NRx2 envelope/value written during note processing. |
| `$C0E6-$C0E7` | `SOUND_WAVE_PATTERN_MAIN` / `SOUND_WAVE_PATTERN_ALT` | High | Waveform selector for wave channels `C=2` and `C=6`. |
| `$C0E8-$C0EB` | `SOUND_MAIN_TEMPO_*` / `SOUND_SFX_TEMPO_*` | Medium | Tempo/multiplier pairs selected by `$ED`; split for channels `<4` and `>=4`. |
| `$C0EC-$C0ED` | `SOUND_INDEX_PTR_*` | High | Temporary pointer to the selected `SoundIndexTable` entry while expanding multi-channel entries. |

The reset/setup paths now share explicit defaults:
`SOUND_COUNTER_INIT_VALUE` seeds loop counters, note lengths, length scales, and
tempo high bytes with `$01`; `SOUND_OUTPUT_MASK_ALL` initializes the output mask
to `$FF`; `SOUND_SEQUENCE_END_COMMAND` marks a sequence end; and
`SOUND_NR50_RESET_VALUE` restores the master volume/mixing register to `$77`.
`SoundEngine` uses `SOUND_BGM_RESET_SKIP_MAX_COMMAND` and
`SOUND_BGM_RESET_MAX_COMMAND` around the BGM reset path, which clears the
primary-channel pointer bytes (`SOUND_PRIMARY_POINTER_CLEAR_BYTES`) and then
the primary-channel state arrays (`SOUND_PRIMARY_CHANNEL_COUNT`) before
starting the selected sequence.
The full hardware reset path now uses scoped reset values for NR52/NR30 power,
NR10/envelope reset, and NRx4 length-enable writes, plus clear spans derived
from the sound WRAM layout (`SOUND_HW_RESET_ZERO_CLEAR_BYTES` and
`SOUND_HW_RESET_COUNTER_CLEAR_BYTES`).
`SOUND_NOTE_LENGTH_SEQUENCE_STEP_VALUE` names the note-length value that causes
`TickSoundChannel` to stop decrementing and advance the sequence parser.
`SOUND_FIXED_TEMPO_HI/LO` names the `$0100` multiplier used by channel 7 in the
SFX/fixed-tempo branch before note length is scaled.
`SOUND_BGM_ACTIVE_ID_GATE` names the shared `$0F` boundary used by BGM active-ID
checks, channel-7 command priority checks, NR50 restore gating, and sequence
rewind gating.
`SoundChannelEnableMaskTable` and `SoundChannelDisableMaskTable` now express
the repeated channel-slot-to-`rNR51` mapping with
`SOUND_OUTPUT_CH1..4_TERMINAL_BITS` and `SOUND_OUTPUT_CH1..4_CLEAR_MASK`;
the channel-3 wave-update masks are aliases of the same channel-3 values.
The helper code also names `SOUND_WAVE_RAM_FILL_VALUE`,
`SOUND_WAVE_RAM_END_LOW`, `SOUND_WAVE_OUTPUT_TERMINAL_BITS`,
`SOUND_WAVE_OUTPUT_TERMINAL_CLEAR_MASK`, `SOUND_WAVE_TRIGGER_VALUE`,
`SOUND_WAVE_UPDATE_END_MARKER`, `SOUND_WAVE_PATTERN_LAST_BYTE_INDEX`,
`SOUND_WAVE_LEVEL_PARAM_BITS`, `SOUND_VIBRATO_FREQ_MAX`, and
`SOUND_REGISTER_PAGE_HI` for the wave-update, vibrato-clamp, and
hardware-register address paths.
The vibrato and note-output paths now also use scoped masks and offsets:
`SOUND_VIBRATO_PHASE_COUNTER_MASK` is the low-nibble counter in
`SOUND_CH_VIBRATO_PHASE`; `SOUND_VIBRATO_DEPTH_SUBTRACT_MASK` and
`SOUND_VIBRATO_DEPTH_ADD_MASK` split the packed down/up depth in
`SOUND_CH_VIBRATO_DEPTH`; `SOUND_DUTY_BITS_MASK` and
`SOUND_LENGTH_BITS_MASK` split NRx1 duty bits from the low six length bits.
`SoundUpdate3` uses `SOUND_REGISTER_DUTY_LENGTH_OFFSET`,
`SOUND_REGISTER_ENVELOPE_OFFSET`, and `SOUND_REGISTER_FREQ_LO_OFFSET` as the
small register offset added to the per-channel base in
`SoundRegisterOffsetTable`; the table now names the channel hardware base lows
with `SOUND_REGISTER_CH*_BASE_LOW` constants derived from `rNR10`, `rNR21`,
`rNR30`, and `rNR41`, and emits one `SOUND_REGISTER_OFFSET_ENTRY` per channel
slot.
`SoundChannelEnableMaskTable` and `SoundChannelDisableMaskTable` now emit one
`SOUND_CHANNEL_MASK_ENTRY` per channel slot, matching the `rNR51` masks used by
`UpdateSoundChannelOutputMask`.
The note and pause hardware paths now use `AUD3ENA_ON/OFF` for NR30 wave
channel toggles, `SOUND_REST_ENVELOPE_VALUE` for the silent rest envelope byte,
and `SOUND_FREQ_HIGH_RESTART_KEEP_MASK` when combining a frequency high byte
with the NRx4 restart and length bits.
The pitch helper also now names `SOUND_PITCH_SHIFT_TARGET_OCTAVE`, the octave
shift loop's stop value, and `SOUND_PITCH_FREQ_HIGH_BIAS`, the high-byte bias
added after the base pitch has been shifted. `SoundPitchBaseTable` entries are
emitted as `SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_0..11`; the index
comes from note command low nibbles and `$EB` pitch-slide operands, so the names
deliberately avoid asserting note letters. `SOUND_PITCH_SLIDE_MIN_TICKS` names
the one-tick clamp when the computed pitch-slide duration would underflow.
`SOUND_SEQUENCE_REWIND_LOW_BYTE_DELTA` and
`SOUND_SEQUENCE_REWIND_HIGH_BYTE_DELTA` name the one-byte rewind applied to a
channel sequence pointer when the BGM active-ID gate asks the parser to revisit
the previous sequence byte.
Channel-index comparisons in the parser and setup code now use
`SOUND_PRIMARY_CHANNEL_COUNT`, `SOUND_LAST_CHANNEL_INDEX`,
`SOUND_PRIMARY_WAVE_CHANNEL_INDEX`, `SOUND_CHANNEL3_INDEX`, and
`SOUND_SECONDARY_WAVE_CHANNEL_INDEX`. `StoreSoundBgmActiveState` also uses
`SOUND_SECONDARY_WAVE_SEQUENCE_PTR_OFFSET` when it points channel 6 at the
one-byte `SoundWaveDutyData` end marker after installing low-ID BGM active
state.

## Wave Pattern Table

`ProcessNote` indexes `SoundWavePatternPointerTable` at `01:$7DBD` for wave channels (`C=2` and `C=6`), then
copies 16 bytes from the selected pointer to `_AUD3WAVERAM` (`$FF30-$FF3F`)
with NR30 disabled before re-enabling the wave channel. The copy loop seeds
`B` with `SOUND_WAVE_PATTERN_LAST_BYTE_INDEX`, which produces the 16 wave-RAM
bytes, and the length/envelope parser uses `SOUND_WAVE_LEVEL_PARAM_BITS` before
shifting the selected wave-output level into NRx2 format.

| Range | Label | Meaning |
|-------|-------|---------|
| `01:$7DBD-$7DCE` | `SoundWavePatternPointerTable` | Nine `SOUND_WAVE_PATTERN_POINTER` records to wave pattern bytes. |
| `01:$7DCF-$7DFE` | `SoundWavePatternData_0` through `SoundWavePatternData_2` | Three dedicated 16-byte wave patterns, each emitted as two `SOUND_WAVE_PATTERN_ROW` records. |
| `01:$7DFF` | `SoundWavePatternData_SharedSequence` / `SoundSequenceData_7dff` | Shared address used both as a wave pointer target and a sound sequence target; it stays as sequence `db` because the first 16 bytes are dual-use. |

The early channel-7 effect sequences at `01:$7D85-$7DBC` are emitted as
`SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE param0, param1`: one `$20`
extended-note command, two channel-7 operands, and `SOUND_SEQUENCE_END_COMMAND`.
Longer channel-7 streams use `SOUND_CHANNEL7_EXTENDED_NOTE note, param0,
param1` for the same two-operand command shape. The operand names stay generic
until the channel-7 hardware write semantics are fully decoded.

`SoundSequenceData_7e15`, the channel-5 half of the pause sound pair
(`SoundIndexEntry_Pause` starts a count-2 entry at channel 4, followed by
`SoundIndexEntry_2f`), now uses `SOUND_DUTY_LENGTH`, repeated
`SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END`. The channel-4 half at
`SoundSequenceData_7dff` stays raw because it is also the shared wave-pattern
pointer target at `01:$7DFF`.

The first thirteen short effect sequences (`SoundSequenceData_7e2c`, `7e4b`, `7e5c`,
`7eb4`, `7ec7`, `7eda`, `7eeb`, `7ef6`, `7f29`, `7f34`, `7f43`, `7f52`,
and `7f9d`) now use generic duty, sweep, extended-note, and end records
(`SOUND_SWEEP` appears only where the original stream has a `$10` command).
These records document the command stream without assigning hardware-specific
meaning to the extended-note operands yet.

The tail-adjacent short sequences at `SoundSequenceData_7f0d`, `7fb4`, `7fd0`,
and `7fe3` now use the same duty/extended-note/end records. `7f0d` and `7fb4`
fall through to the shared end-only labels `SoundSequenceData_7f1b` and
`SoundSequenceData_7fc2`. The adjacent channel-7 entries `7f1c` and `7fc3` use
four `SOUND_CHANNEL7_EXTENDED_NOTE` records followed by `SOUND_SEQUENCE_END`.
`SoundSequenceData_7fe3` ends at `01:$7FF5`; the final `01:$7FF6-$7FFF` bytes
are separated as `Bank1TailPaddingData`, five repeated little-endian `$3900`
padding words.

The adjacent channel-4/5 tail streams at `SoundSequenceData_7f65` and `7f80`
now use generic records for their mixed command tails: four
`SOUND_EXTENDED_NOTE` records, `SOUND_GATE_FLAG`, `SOUND_LENGTH_ENVELOPE`,
`SOUND_OCTAVE`, `SOUND_PITCH_SLIDE`, and `SOUND_SEQUENCE_END`. `7f80` also
contains a second `SOUND_DUTY_LENGTH` command before the gate flag. The
`SOUND_LENGTH_ENVELOPE` macro is intentionally limited to the command form that
consumes the following parameter byte.

The channel-4 board-scan step effects at `01:$7E67-$7EB3` are emitted as
`SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE duty, sweep, note, envelope, freq_lo,
freq_hi, final_sweep`. These are the `SoundIndexEntry_BoardScanStep0..6`
targets, and the seven entries keep the same command layout while stepping the
explicit frequency-low operand from `$C0` down to `$00`.

`HandleWaveUpdate` is a separate VBlank-time `WAVE_UPDATE` path. It fills wave
RAM with `SOUND_WAVE_RAM_FILL_VALUE` through `SOUND_WAVE_RAM_END_LOW`, enables
the wave channel with `AUD3ENA_ON`, sets and later clears
`SOUND_WAVE_OUTPUT_TERMINAL_BITS` in `rNR51`, triggers `rNR34` with
`SOUND_WAVE_TRIGGER_VALUE`, then walks bytes from `UpdateSoundChannels` until
`SOUND_WAVE_UPDATE_END_MARKER`, shifting each source byte into `rNR32` one bit
at a time. The exact audible purpose of this code-byte pattern path remains
unresolved, so the label is intentionally scoped to the flag it handles rather
than to the normal selected wave-pattern copy.

## Command Bytes

| Command | Operands | Current interpretation |
|---------|----------|------------------------|
| `$FF` / `SOUND_SEQUENCE_END_COMMAND` | none | End sequence, or return from saved `$FD` pointer if flag bit 1 is set. |
| `$FD` / `SOUND_SUBSEQUENCE_CALL_COMMAND` | `lo hi` | Sub-sequence call/jump. Saves the current pointer in `SOUND_CH_RETURN_PTRS`, sets flag bit 1, then jumps to the target pointer. |
| `$FE` / `SOUND_LOOP_JUMP_COMMAND` | `count lo hi` | Loop/jump. `count=0` is an unconditional jump. Otherwise `SOUND_CH_LOOP_COUNTER+C` counts iterations before the target is skipped, then resets to `SOUND_COUNTER_INIT_VALUE`. |
| `$10` / `SOUND_SWEEP_COMMAND` | `value` | Writes the following byte to `rNR10` for channels `>=4` when gate suppression is clear. |
| `$20-$2F` / `SOUND_EXTENDED_NOTE_COMMAND_BASE` | command-specific | Extended note path for channels 3-7 when gate suppression is clear. |
| `$B0-$BF` / `SOUND_CHANNEL3_NESTED_COMMAND_BASE` | optional `sound_id` | Channel-3 nested-sound shortcut path. |
| `$C0-$CF` / `SOUND_REST_NOTE_COMMAND_BASE` | none | Rest/silent note high-nibble path. |
| `$D0-$DF` / `SOUND_LENGTH_ENVELOPE_COMMAND_BASE` | sometimes one extra byte | Stores low nibble in `SOUND_CH_LENGTH_SCALE+C`; for most channels also consumes one parameter byte and updates tuning/wave-related state. |
| `$E0-$EF` / `SOUND_OCTAVE_COMMAND_BASE` | command-specific | Several extended commands; unhandled `$E*` stores the low nibble in `SOUND_CH_OCTAVE+C`. |
| `$E8` / `SOUND_FREQ_CARRY_TOGGLE_COMMAND` | none | Toggles flag bit 0 in `SOUND_CH_FLAGS+C`. |
| `$EA` / `SOUND_VIBRATO_COMMAND` | `delay packed` | Sets delay reload/current delay and nibble-packed modulation/timing values. |
| `$EB` / `SOUND_PITCH_SLIDE_COMMAND` | `param packed note` | Sets pitch/slide state, computes a pitch target through `SoundPitchBaseTable`, then processes the following note parameter. |
| `$EC` / `SOUND_DUTY_LENGTH_COMMAND` | `flags` | Stores the upper two bits of the operand into `SOUND_CH_DUTY_LENGTH+C`. |
| `$ED` / `SOUND_TEMPO_COMMAND` | `lo hi` | Sets a global pitch/base pair for channels `<4` or `>=4` and clears related accumulators. |
| `$EE` / `SOUND_OUTPUT_MASK_COMMAND` | `mask` | Stores a channel enable/mute mask in `SOUND_OUTPUT_MASK`. |
| `$EF` / `SOUND_NESTED_SOUND_COMMAND` | `sound_id` | Starts another sound through `SoundEngine`, then returns to the current sequence. |
| `$FC` / `SOUND_DUTY_ROTATE_COMMAND` | `flags` | Stores a rotating/flag byte in `SOUND_CH_DUTY_ROTATE+C` and `SOUND_CH_DUTY_LENGTH+C`, then sets flag bit 6. |
| `$F0` / `SOUND_MASTER_VOLUME_COMMAND` | `value` | Writes master volume/mixing value to `rNR50`. |
| `$F1` / `SOUND_VISUAL_UPDATE_COMMAND` | none | Calls `ApplySoundVisualUpdateCommand`; currently used by menu/BGM animation sequences. |
| `$F8` / `SOUND_GATE_FLAG_COMMAND` | none | Sets `SOUND_CH_GATE_SUPPRESS_BIT` in `SOUND_CH_GATE_FLAGS+C`. |

The source now labels the command-dispatch chain with conservative names:
`DispatchSoundNonEndCommand`, `CheckSoundLoopJumpCommand`,
`CheckSoundLengthEnvelopeCommand`, and `CheckSoundExtendedCommand`. These names
describe the parser branch points without pretending the full sequence language
has been recovered.
The source also now uses `SOUND_COMMAND_HIGH_NIBBLE_MASK` and
`SOUND_COMMAND_LOW_NIBBLE_MASK` for the command-byte nibble splits in the
parser.

The first layers of command-local branches are also named by observed side
effects. `$FF` sequence-end handling now distinguishes
`ReturnFromSoundSubsequence`, `DisableSoundChannelOutputOnEnd`, and
`ClearSoundChannelActiveId`. `$FE` loop handling uses
`IncrementSoundLoopCounter` and `JumpSoundSequenceToLoopTarget`. The
`$D0-$DF` branch uses `StoreWavePatternSelectorAndEnvelope`,
`StoreSoundEnvelope`, and `ContinueSoundCommandParsing`. The `$E8/$EA/$EB`
extended checks are named `CheckSoundVibratoCommand` and
`CheckSoundPitchSlideCommand`. The next extended-command layer names
`CheckSoundDutyLengthCommand`, `CheckSoundTempoCommand`,
`CheckSoundOutputMaskCommand`, `CheckNestedSoundCommand`,
`CheckSoundDutyRotateCommand`, and `CheckSoundMasterVolumeCommand`. The
following layer names `CheckSoundVisualUpdateCommand`,
`CheckSoundGateFlagCommand`, `CheckSoundOctaveCommand`,
`CheckSoundExtendedNoteCommand`, `CheckSoundSweepCommand`, and the channel-3
nested sound branch. The exact command-language names remain documented at the
byte level above.

The note/output layer now names the computed note-length and hardware-output
branches: `ProcessSoundNoteCommand`, `UseMainSoundTempo`,
`UseSfxOrFixedSoundTempo`, `StoreScaledSoundNoteLength`,
`ProcessSoundNoteHighNibble`, rest handling for wave and non-wave channels,
`ProcessPitchedSoundNote`, `WriteSoundEnvelopeAndEnableOutput`,
`UpdateSoundChannelOutputMask`, `ApplySoundOutputMask`,
`WriteSoundChannelOutputMask`, and `WriteSoundChannelLengthRegister`.

The following hardware-facing helpers are now locally named as well:
`LoadWavePatternForSoundNote`, `LookupSoundWavePatternPointer`,
`CopySoundWavePatternToWaveRamLoop`, `WriteSoundFrequencyAndTrigger`,
`StoreSoundPitchSlideFrequency`, `StoreSoundPitchSlideTickCount`,
`InitSoundPitchSlideAscending`, `CalculateSoundPitchSlideStep`,
`DivideSoundPitchSlideDeltaLoop`, and `StoreSoundPitchSlideStep`.
`SoundUpdate3/4/5` now expose their register-offset, multiply, and pitch-table
shift loops, while `SoundLookupIndex` names the priority checks and per-channel
state clear before `StartSoundSequence` installs a new entry.

## Next Work

- Continue refining command-handler labels only after each command's exact role
  is proven.
- Keep numeric `SoundIndexEntry_*` continuation labels until new runtime/player
  evidence proves an audible role beyond their adjacent-table-entry function.
- Refine the medium-confidence `SOUND_CH_*` names after more sequence examples are decoded.
