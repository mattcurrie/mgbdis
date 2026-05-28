# Bank 1 Sound/Music Engine Notes

This document records the current recovered model of the Bank 1 sound sequence
interpreter. Names are conservative until the command format is fully decoded.

## Confirmed Entry Points

| Address | Label | Role |
|---------|-------|------|
| `01:$53CF` | `SoundEngine` | Public sound/BGM command entry. Handles stop/reset cases, then selects a sound table entry. |
| `01:$53F7` | `SoundLookupIndex` | Converts a sound index into a three-byte table entry under `$7C2C`. |
| `01:$55E2` | `StartSoundSequence` | Expands the selected sound entry into per-channel sequence pointers and active sound IDs. |
| `01:$4D4E` | `SoundSequenceStep` | Per-channel sequence tick; reloads delay and dispatches command parsing. |
| `01:$4D65` | `CountdownSequence` | Reads sequence bytes and executes commands until a note/delay/end condition stops the tick. |

## Sound Index Table

`SoundLookupIndex` and `StartSoundSequence` use `index * 3 + $7C2C`.
The recovered table covers sound indexes `$00-$72`.

| Range | Label | Format |
|-------|-------|--------|
| `01:$7C2C-$7D84` | `SoundIndexTable`, `SoundIndexEntry_*` | `db flags`, `dw sequence_pointer` |

The first byte packs channel/priority information used by `StartSoundSequence`.
The pointer can target either the main stream at `$569A-$7C01` or short sound
effects in the tail region at `$7D85-$7FFE`.

The entry at `$569A` is important: it proves the pitch table ends at `$5699`.
`$569A` starts a real sequence (`$ED,$00,...`) even though it was previously
included as the last word of `SoundPitchBaseTable`.

## Confirmed Sound IDs

These names are based on direct `PlaySound` call sites. Numeric
`SoundIndexEntry_*` labels remain in the table; the source also adds alias
labels for the confirmed entries.

| ID | Constant | Sound table alias | Evidence |
|----|----------|-------------------|----------|
| `$1B` | `SND_DROP_START` | `SoundIndexEntry_DropStart` | Called immediately before `StartDropAnim` when a down/drop input starts the drop animation. |
| `$25` | `SND_BOARD_SCAN_STEP_BASE` | `SoundIndexEntry_BoardScanStepBase` | `ScanBoard` plays `SND_BOARD_SCAN_STEP_BASE - c` while its scan animation step counter advances. |
| `$26` | `SND_COMMIT_PIECE` | `SoundIndexEntry_CommitPiece` | Called by `CommitFallingPieceToBoard`, the code path that writes the falling piece into the board state. |
| `$27` | `SND_PIECE_LAND` | `SoundIndexEntry_PieceLand` | Called by `HandlePieceLanding` after updating the board and moving the piece down. |
| `$28` | `SND_CURSOR_MOVE` | `SoundIndexEntry_CursorMove` | Used by menu cursor movement and simple left/right movement feedback. |
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
| `$54` | `SND_CONFIRM` | `SoundIndexEntry_Confirm` | Called by `PlayConfirmSound` and start/ready transitions. |
| `$FF` | `SND_STOP_ALL` / `SND_BGM_OFF` | n/a | Stop command; also stored as the BGM-off sentinel. |

## Core State Arrays

The channel index is in `C`. Most arrays are indexed by `C`; pointer arrays use
`C * 2`.

| Range | Constant | Confidence | Meaning |
|-------|----------|------------|---------|
| `$C000` | `SOUND_STATUS` | Low | Cleared by sound reset; no direct read confirmed yet. |
| `$C001` | `SOUND_COMMAND_ID` | High | Last sound command/index passed to `SoundEngine`; used for priority checks and table lookup. |
| `$C002` | `SOUND_PAUSE_FLAG` | High | Set by `PauseGame`, cleared by `UnpauseGame`; also gates link/sound updates and uses bit 7 after pause muting is applied. |
| `$C003` | `SOUND_DEFERRED_ID` | Medium | Deferred/nested sound ID state used around `$EF` nested sound starts and channel 6 sequence end. |
| `$C004` | `SOUND_OUTPUT_MASK` | High | Channel enable mask written by `$EE` and combined with `rNR51`. |
| `$C005` | `SOUND_NR50_BACKUP` | High | Saved `rNR50` value restored after low-index music/SFX priority handling. |
| `$C006-$C015` | `SOUND_CH_SEQUENCE_PTRS` | High | Current sequence pointer per channel, low/high pairs. `SoundUpdate2` reads and advances this pointer. |
| `$C016-$C025` | `SOUND_CH_RETURN_PTRS` | High | Saved return pointer for `$FD` sub-sequence calls. |
| `$C026-$C02D` | `SOUND_CH_ACTIVE_ID` | High | Active sound/priority ID per channel. Cleared when a sequence ends. |
| `$C02A-$C02D` | `SOUND_BGM_ACTIVE_ID` | Medium | Four-byte music priority gate set for low sound IDs. This overlaps the last four active-ID entries. |
| `$C02E-$C035` | `SOUND_CH_FLAGS` | Medium | Per-channel flags. Observed bits include `$02` return pending, `$10/$20` slide state, `$40` rotating register state. |
| `$C036-$C03D` | `SOUND_CH_GATE_FLAGS` | Medium | Secondary per-channel flags; bit 0 suppresses selected note/gate writes. |
| `$C03E-$C045` | `SOUND_CH_DUTY_LENGTH` | Medium | Cached NRx1 duty/length bits used before hardware register writes. |
| `$C046-$C04D` | `SOUND_CH_DUTY_ROTATE` | Medium | Rotating duty bits loaded by `$FC` and advanced by `SoundUpdate1`. |
| `$C04E-$C055` | `SOUND_CH_DELAY` | High | Current delay counter per channel. |
| `$C056-$C05D` | `SOUND_CH_VIBRATO_DEPTH` | Medium | Packed vibrato up/down depth loaded by `$EA`. |
| `$C05E-$C065` | `SOUND_CH_VIBRATO_PHASE` | Medium | Packed vibrato reload/counter nibble loaded by `$EA`. |
| `$C066-$C06D` | `SOUND_CH_FREQ_LO_BASE` | Medium | Base low-frequency byte used by vibrato before writing NRx3. |
| `$C06E-$C075` | `SOUND_CH_DELAY_RELOAD` | High | Delay reload value per channel. |
| `$C076-$C0B5` | `SOUND_CH_SLIDE_*`, `SOUND_CH_FREQ_*`, `SOUND_CH_SLIDE_TARGET_*` | Medium | Pitch-slide state loaded by `$EB` and maintained by `Jump_001_524c`/`UpdateObjectData`. |
| `$C0B6-$C0BD` | `SOUND_CH_NOTE_LENGTH` | Medium | Computed note length / NRx1 length source used by `Display2PStatus` and `GetMusicPointer`. |
| `$C0BE-$C0C5` | `SOUND_CH_LOOP_COUNTER` | High | `$FE` loop counter per channel. |
| `$C0C6-$C0CD` | `SOUND_CH_LENGTH_SCALE` | Medium | Per-channel length scale loaded by `$D0-$DF`. |
| `$C0CE-$C0D5` | `SOUND_CH_TEMPO_ACCUM` | Medium | Per-channel fractional accumulator used when multiplying note length by tempo. |
| `$C0D6-$C0DD` | `SOUND_CH_OCTAVE` | Medium | Pitch table shift count loaded by `$E0-$EF` low nibble. |
| `$C0DE-$C0E5` | `SOUND_CH_ENVELOPE` | Medium | Cached NRx2 envelope/value written during note processing. |
| `$C0E6-$C0E7` | `SOUND_WAVE_PATTERN_MAIN` / `SOUND_WAVE_PATTERN_ALT` | High | Waveform selector for wave channels `C=2` and `C=6`. |
| `$C0E8-$C0EB` | `SOUND_MAIN_TEMPO_*` / `SOUND_SFX_TEMPO_*` | Medium | Tempo/multiplier pairs selected by `$ED`; split for channels `<4` and `>=4`. |
| `$C0EC-$C0ED` | `SOUND_INDEX_PTR_*` | High | Temporary pointer to the selected `SoundIndexTable` entry while expanding multi-channel entries. |

## Wave Pattern Table

`ProcessNote` indexes `01:$7DBD` for wave channels (`C=2` and `C=6`), then
copies 16 bytes from the selected pointer to wave RAM.

| Range | Label | Meaning |
|-------|-------|---------|
| `01:$7DBD-$7DCE` | `WavePatternPointerTable` | Nine 16-bit pointers to wave pattern bytes. |
| `01:$7DCF-$7DFE` | `WavePatternData_7dcf` through `WavePatternData_7def` | Three dedicated 16-byte wave patterns. |
| `01:$7DFF` | `WavePatternData_7dff` / `SoundSequenceData_7dff` | Shared address used both as a wave pointer target and a sound sequence target. |

## Command Bytes

| Command | Operands | Current interpretation |
|---------|----------|------------------------|
| `$FF` | none | End sequence, or return from saved `$FD` pointer if flag bit 1 is set. |
| `$FD` | `lo hi` | Sub-sequence call/jump. Saves the current pointer in `SOUND_CH_RETURN_PTRS`, sets flag bit 1, then jumps to the target pointer. |
| `$FE` | `count lo hi` | Loop/jump. `count=0` is an unconditional jump. Otherwise `SOUND_CH_LOOP_COUNTER+C` counts iterations before the target is skipped. |
| `$D0-$DF` | sometimes one extra byte | Stores low nibble in `SOUND_CH_LENGTH_SCALE+C`; for most channels also consumes one parameter byte and updates tuning/wave-related state. |
| `$E0-$EF` | command-specific | Several extended commands; unhandled `$E*` stores the low nibble in `SOUND_CH_OCTAVE+C`. |
| `$E8` | none | Toggles flag bit 0 in `SOUND_CH_FLAGS+C`. |
| `$EA` | `delay packed` | Sets delay reload/current delay and nibble-packed modulation/timing values. |
| `$EB` | `param packed note` | Sets pitch/slide state, computes a pitch target through `SoundPitchBaseTable`, then processes the following note parameter. |
| `$EC` | `flags` | Stores the upper two bits of the operand into `SOUND_CH_DUTY_LENGTH+C`. |
| `$ED` | `lo hi` | Sets a global pitch/base pair for channels `<4` or `>=4` and clears related accumulators. |
| `$EE` | `mask` | Stores a channel enable/mute mask in `SOUND_OUTPUT_MASK`. |
| `$EF` | `sound_id` | Starts another sound through `SoundEngine`, then returns to the current sequence. |
| `$FC` | `flags` | Stores a rotating/flag byte in `SOUND_CH_DUTY_ROTATE+C` and `SOUND_CH_DUTY_LENGTH+C`, then sets flag bit 6. |
| `$F0` | `value` | Writes master volume/mixing value to `rNR50`. |
| `$F1` | none | Calls `CheckGameStateUpdate`; currently used by menu/BGM animation sequences. |
| `$F8` | none | Sets bit 0 in `SOUND_CH_GATE_FLAGS+C`. |

## Next Work

- Rename command-handler labels only after each command's exact role is proven.
- Assign semantic names to `SoundIndexEntry_*` values once call sites are traced.
- Refine the medium-confidence `SOUND_CH_*` names after more sequence examples are decoded.
