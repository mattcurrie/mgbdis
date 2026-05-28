# Findings & Decisions

## Requirements
- Recover the lost Game Boy YOSSY NO TAMAGO source from the existing ROM/disassembly.
- Preserve behavior and use the current ROM as ground truth.
- Improve labels, comments, memory maps, bank structure, and data/code separation.
- Prefer evidence-backed recovery over speculative rewriting.
- Aim for the best attainable source reconstruction, accepting a long-running iterative process.

## Known Facts
- ROM path: `Yoshi/yoshi.gb`
- Built/rebuilt path also present: `Yoshi/game.gb`
- Both are 65,536 bytes.
- Header title is `YOSSY NO TAMAGO` at `0x0134`.
- Cartridge type is `0x01` = MBC1.
- ROM size code is `0x01` = 64KB.
- RAM size code is `0x00` = no external RAM.
- Bank layout:
  - Bank 0: fixed `ROM0[$0000-$3FFF]`
  - Bank 1: switch window `ROMX[$4000-$7FFF], BANK[$1]`
  - Bank 2: switch window graphics data, `BANK[$2]`
  - Bank 3: switch window graphics data, `BANK[$3]`
- Runtime pattern observed:
  - Bank 1 is the normal active switch bank.
  - Bank 2/3 are selected temporarily for graphics copies, then Bank 1 is restored.
  - VBlank handler lives in Bank 1 at `$4B59`, so Bank 1 must be active during normal LCD-on execution.

## User Testimony
- User programmed the GB version with Yuji Shinkai.
- Original source is lost.
- GB version was allowed to use 64KB by Nintendo to shorten development.
- FC version was created later in about five weeks.

## Research Findings
- `Yoshi/bank_000.asm` contains bank switch writes to `$2100`.
- Examples:
  - Title initialization switches to Bank 2, copies graphics to VRAM, then restores Bank 1.
  - Game initialization switches to Bank 2 for game tiles, then restores Bank 1.
  - Several transition/result paths switch to Bank 3 for graphics, then restore Bank 1.
- `Yoshi/yoshi.sym` already contains high-level bank annotations and many labels.
- `Yoshi/ARCHITECTURE.md` contains an existing architecture summary that should be validated rather than blindly trusted.
- Simple ASCII searches found no visible `AKIHITO`, `koriyama`, or Game Freak credit strings in `Yoshi/yoshi.gb` or `Yoshi/game.gb`.
- `make -B` in `Yoshi/` rebuilds `Yoshi/game.gb` byte-for-byte identical to `Yoshi/yoshi.gb`.
- `Yoshi/yoshi.gb` and rebuilt `Yoshi/game.gb` both have SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
- The VRAM copy HRAM block is now evidence-aligned:
  - `$FFAE` = `VRAM_COPY_BLOCKS`, a 16-byte block count used by `VRAMCopyDMA`.
  - `$FFAF/$FFB0` = source pointer low/high.
  - `$FFB1/$FFB2` = destination pointer low/high.
  - `$FFB3` = second/alternate block count candidate from `VRAMCopySetup`; role still needs confirmation.
- `tools/recovery_refs.py` provides a repeatable WRAM/HRAM reference summary for `bank_000.asm` and `bank_001.asm`.
- The high-frequency reference scan highlights fake code references inside sound/music data. The previous assumption that all of `01:$55E2-$5FE2` was data was too broad: `$55E2-$5668` is executable sound setup code, while later ranges still need sequence/data boundary recovery.
- `GAME_STATE` (`$FFC7`) has seven observed values, now defined in `Yoshi/constants.inc`:
  - `$00` title init
  - `$01` title menu
  - `$02` play setup
  - `$03` playing
  - `$04` round end/result/high-score
  - `$05` pre-play settings/start-wait loop
  - `$06` pre-play one-shot init
- `docs/source_recovery/state_machine.md` records the current state meanings and observed transitions.
- The old `PLAYER_MODE` name at `$C671` was misleading. Evidence shows `$C671` is an active A/B-style game type, while 1P/2P is controlled by `TWO_PLAYER_FLAG` at `$C6B6`; it is now named `GAME_TYPE`.
- The settings bytes `$C6B2-$C6B5` are now named `OPTION_GAME_TYPE`, `OPTION_LEVEL`, `OPTION_SPEED`, and `OPTION_BGM`.
- The active gameplay copies `$C6B7-$C6B8` are now named `ACTIVE_LEVEL` and `ACTIVE_SPEED`.
- `docs/source_recovery/options_variables.md` records the current evidence for these settings variables.
- Bank 1 range `01:$40A0-$42F4` is sprite update data, not executable code. It is now represented as `SpriteUpdatePointerTable` plus `SpriteUpdateData_*` `dw`/`db` blocks.
- The temporary compatibility `DEF` symbols that were needed for later fake-code references have been removed; after the music stream conversion, no references to those fake labels remain.
- `docs/source_recovery/data_ranges.md` records converted and remaining high-priority data ranges.
- Bank 1 range `01:$55E2-$5668` is executable sound setup code. It is now represented as `StartSoundSequence`, because both `SoundEngine` and `SoundLookupIndex` jump to it and it expands a selected sound entry into channel state arrays before returning.
- Bank 1 sound support tables immediately after that code have been split and labeled:
  - `01:$5669` = `SoundWaveDutyData`
  - `01:$566A-$5671` = `SoundRegisterOffsetTable`
  - `01:$5672-$5679` = `SoundChannelDisableMaskTable`
  - `01:$567A-$5681` = `SoundChannelEnableMaskTable`
  - `01:$5682-$5699` = `SoundPitchBaseTable`
- `SoundPitchBaseTable` was shortened from 13 words to 12 words. `SoundIndexTable` points to `$569A`, proving `$569A` is the first sound sequence byte (`SoundSequenceData_569a`) rather than pitch table data.
- Bank 1 sequence block `01:$569A-$5FE2` was already mostly `db`, but now has internal pointer-target labels from `SoundSequenceData_569a` through `SoundSequenceData_5f30`.
- Bank 1 music sequence data labels were added at exact `yoshi.sym` data boundaries:
  - `01:$7191-$71C0` = `MusicSequenceData_7191`
- Bank 1 apparent-code music sequence blocks were recovered as data:
  - `01:$5FE3-$7190` = `MusicSequenceData_5fe3` through `MusicSequenceData_6f92`
  - `01:$71C1-$71E3` = `MusicSequenceData_71c1` with internal boundaries at `MusicSequenceData_71c2` and `MusicSequenceData_71d5`
  - `01:$71E4-$77B5` = `MusicSequenceData_71e4` through `MusicSequenceData_779b`, including the earlier `$73B3` fake-code island
  - `01:$77B6-$7805` = `MusicSequenceData_77b6` with an internal boundary at `MusicSequenceData_77c5`
- Bank 1 range `01:$7806-$7C01` was recovered as music sequence data with internal labels at local `$FD/$FE` pointer targets.
- Bank 1 range `01:$7C02-$7C07` is a real six-byte helper reached by two Bank 0 `call $7c02` sites. It is now labeled `TickBgmPreviewTimer`; the adjacent `CheckGameStateUpdate` routine still starts at `01:$7C08`.
- The Bank 1 sound/music stream is now explicit data from `01:$569A-$7C01`, with first-pass labels at `$FD/$FE` pointer targets.
- Bank 1 tail data was recovered:
  - `01:$7C2C-$7D84` = `SoundIndexTable`, a 115-entry table of one flags byte plus one sequence pointer.
  - `01:$7DBD-$7DCE` = `WavePatternPointerTable`, used by wave-channel note processing.
  - `01:$7DCF-$7FFE` = wave pattern bytes and short sound sequence data, replacing fake `Call_001_7f9d`/`jr_001_7*` labels.
- `docs/source_recovery/sound_engine.md` now records the first-pass command format for the Bank 1 sound/music interpreter, including `$FD` sub-sequence calls, `$FE` loops, `$FF` end/return, and the main per-channel state arrays.
- Sound engine WRAM `$C000-$C0ED` is now represented by `SOUND_*` constants in `Yoshi/constants.inc`. High-confidence fields include current/return sequence pointers, active sound IDs, pause gating, output mask, loop counters, wave selectors, and the sound-index temporary pointer; slide/tempo/envelope fields remain medium-confidence and are documented that way.
- High-confidence sound IDs from `PlaySound` call sites are now named (`SND_DROP_START`, `SND_COMMIT_PIECE`, `SND_PIECE_LAND`, `SND_CURSOR_MOVE`, `SND_ROUND_COMPLETE`, `SND_PAUSE`, `SND_TITLE_BGM`, `SND_BGM_OPTION*/PREVIEW*`, `SND_LINK_MASTER/SLAVE`, `SND_CONFIRM`, `SND_STOP_ALL`) and matching alias labels were added to `SoundIndexTable`.
- Bank 0 range `00:$15FE-$1611` is `LevelFallDelayTable`, not code. `ProcessFalling` indexes it by active level to seed the fall timer, and the real code entry at `00:$1612` is now `UpdateLandingProgress`, falling through to `CommitFallingPieceToBoard` at `00:$162A`.
- Bank 0 range `00:$18CB-$18E3` is round-complete data after `HandlePieceLanding`, not code. `$18CB-$18D1` remaps `SCREEN_STATE`, and `$18D2-$18E3` is a big-endian parameter table loaded into `HL` before calling `$432F`; `CalcResults` starts at `00:$18E4`.
- Bank 1 `01:$432F` is now labeled `AddScore`. It adds an `HL` packed-BCD score delta into `$C61D-$C61F`, caps at `99999`, and writes five unpacked display digits at `$C621-$C625`.
- Bank 1 `01:$442C-$445B` is `FieldColumnTilePatternTable`, six 16-byte tile patterns selected by `LoadGameBGTiles`; `01:$445C` is real code and is now labeled `StartNextRound`.
- Bank 1 `01:$4681` is now labeled `AdvanceEggAnimation`; it advances the `$C6D3-$C6D5` egg animation counters and is called from the round-complete score/result path.
- Bank 0 `00:$22CC-$230E` and `00:$230F-$234B` are field redraw delta tables. `DrawField2`, `DrawField4`, and `DrawFieldRow` index them until terminator `$10`; the real code entry at `00:$234C` is now `UpdateFieldTimers`.
- `UpdateFieldTimers` is called from both Bank 1 `GameMainUpdate` and Bank 0 `Send2PData`, decrementing four bytes at `$C6CB-$C6CE` and clearing related C2xx display rows when each timer expires.
- Bank 1 `01:$4570` is now labeled `AdvanceSpriteAnimFrame`; title/input code calls it before `SpriteAnimTable` to advance the shared sprite animation frame/state.
- HRAM `$FF80` is now named `OAM_DMA_HRAM`; `SetupOAMDMA` copies the DMA routine there and `VBlankHandler` calls it.
- Bank 0 `00:$33F7` is a real link-start confirmation loop, now labeled `WaitLinkStartConfirm`. It had been hidden behind a short `db` escape.
- Bank 0 `00:$3839-$3FFF` is graphics data, not code. Result setup copies `$3839` and `$3D39` to VRAM through `VRAMCopySetup`; the remaining tail is now explicit `db`.
- MBC1 bank switching is now named in source:
  - `$2100` = `MBC1_ROM_BANK_REG`
  - `$01` = `ROM_BANK_MAIN_CODE`
  - `$02` = `ROM_BANK_GRAPHICS_0`
  - `$03` = `ROM_BANK_GRAPHICS_1`
- Raw `$2100` writes in real code paths were replaced with `MBC1_ROM_BANK_REG`.
- `docs/source_recovery/graphics_loads.md` records the initial Bank 2/3 and ROM0 graphics-to-VRAM copy map, including overlapping destination/source ranges that still need visual decoding.
- `tools/render_gb_tiles.py` now renders Game Boy 2bpp tile ranges directly from `Yoshi/yoshi.gb` as PNG sheets.
- `docs/source_recovery/tile_sheets/` contains first-pass rendered evidence for the observed Bank 2, Bank 3, and ROM0 graphics ranges.
- Visual evidence from the rendered sheets:
  - Bank 2 contains title logo, option/menu labels, gameplay character/egg tiles, numbers, and playfield UI fragments.
  - Bank 3 is heavily result/high-score oriented; visible text includes `CONGRATULATION`, `SCORE`, `LEVEL`, `LOW`, `HIGH`, `TIME`, `RECORD`, `HI SCORE`, `MARIO`, `LUIGI`, and `NEXT`.
  - ROM0 `TitleResultTileData0` / `TitleResultTileData1` render as compact result/count/score tiles, supporting the data classification.
- Bank 3 now has transfer-start labels at the observed load boundaries, and Bank 0 graphics load code refers to those labels instead of raw source addresses.
- After the latest code/data separation, no raw `call $xxxx` / `jp $xxxx` / `jr $xxxx` remains in `bank_000.asm` or `bank_001.asm` from real code paths.
- Temporary compatibility symbols for fake music-data references were removed after the referencing streams were converted from apparent code to explicit `db`.
- `$C6C1` is now `BGM_PREVIEW_TIMER` with medium confidence. `$C6C2` is now `BGM_PREVIEW_PERIOD` with low confidence because it receives BGM-specific values but no direct read has been confirmed yet.
- Bank 0 option UI inline data has been recovered:
  - `00:$1D84-$1DAE` is `$FF`-terminated option label tile text (`A GAME`, `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, `OFF`).
  - `00:$1DAF-$1DBE` is eight option-marker row/column pairs.
  - `00:$1E3D-$1E4F` and `00:$2026-$203A` are row/column/tile triplet lists consumed by `DrawTileTripletList`.
  - `00:$1E75-$1E89` is three 7-byte setting cursor/sprite records copied to `$C290/$C2A0/$C2B0`.
  - `00:$1F4C-$1F4F` and `00:$2C60-$2C63` are option-row upper-bound tables with bytes `$02,$05,$02,$04`.
- The labels `UpdatePaletteFade`, `UpdateHighScore`, `LoadSettings`, and `SaveSettings` were renamed to `DrawOptionTextLabels`, `DrawOptionMarkers`, `DrawOptionMarker`, and `DrawTileTripletList` because their behavior is option UI drawing, not palette/high-score/save handling.
- Bank 0 score/result text data has been recovered:
  - `00:$25C3-$25E0` score header strings selected by `LINK_ROLE`.
  - `00:$2622-$2663` two-line result text blocks selected in `CalcBonus` and `ShowWinScreen`.
  - `00:$2CBC-$2CD6` result header text, decoding to `1 PLAYER GAME` and `YOSSY EGGS`.
  - `00:$2DE0-$2E2D` restart/result two-line text blocks.
  - `00:$2E38-$2E3B` duplicate `OFF` text.
  - `00:$2E7C-$2EB2` BGM marker strings used by `UpdateContinue`.
  - `00:$2734-$2853` preview/result tile table, indexed as six 48-byte three-line entries by `DrawPreview` and `WaitForRestart`.
  - `00:$2FFB-$304A` countdown digit bitmap table, indexed as ten 8-byte records by `UpdateCountdownTimer`.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Use `rg`, `nl`, `sed`, and small scripts for static analysis | Fast local inspection, keeps evidence traceable. |
| Create persistent planning files in the repository root | Source recovery will span many steps and needs durable memory in the project. |
| Start with memory-map recovery | WRAM/HRAM naming will improve routine naming and comments across banks. |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| Planning files were accidentally placed in `/Users/akihito/git` | Re-created them under `/Users/akihito/git/mgbdis` and deleted the misplaced copies. |
| Initial VRAM copy rename changed two HRAM operand bytes | Compared rebuilt ROM to `Yoshi/yoshi.gb`, found real differences at offsets `$4B45/$4B48`, and corrected `VRAMCopyDMA` labels so the build is byte-identical again. |
| First attempt at `FieldRowDeltaTable` had one extra byte and then a byte-order mismatch | Used `make -B`, `cmp -l`, and `xxd` against `Yoshi/yoshi.gb` to restore exact `00:$230F-$234B` bytes and `UpdateFieldTimers` at `00:$234C`. |
| Two Bank 3 graphics labels were first placed at repeated-looking rows, changing `ld hl` immediates for `$5C00` and `$6AB0` | Used an address-counting `awk` check over 16-byte `db` rows, moved the labels to exact `$5C00` and `$6AB0`, then rebuilt byte-identical. |

## Resources
- `Yoshi/yoshi.gb`
- `Yoshi/game.gb`
- `Yoshi/bank_000.asm`
- `Yoshi/bank_001.asm`
- `Yoshi/bank_002.asm`
- `Yoshi/bank_003.asm`
- `Yoshi/yoshi.sym`
- `Yoshi/ARCHITECTURE.md`
- `Yoshi/SERIAL_PROTOCOL.md`

## Open Questions
- Which existing labels came from user/manual analysis versus automatic symbol recovery?
- Does `VRAM_COPY2_BLOCKS` at `$FFB3` drive a second queued VRAM transfer, or is it a setup-time scratch/count used by a narrower path?
- Which game states correspond to demo/attract behavior, if present?
- Which data blocks are currently mis-disassembled as instructions?
- Should the current label `InitGameVars` be renamed to `RunTitleMenu` or a more precise title-loop name after its helper calls are fully traced?
- Should the current labels `OptionsScreen`, `ProcessRoundEndLoop`, and `InitP2Settings` be renamed after the pre-play/result shared drawing paths are fully separated?
- Should `$C672/$C628/$C629`, touched by `AddScore` immediately after score digit unpacking, be named as game-type/result display digits after tracing their draw sites?
