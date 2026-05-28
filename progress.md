# Progress Log

## Session: 2026-05-28

### Phase 1: Baseline & Evidence Inventory
- **Status:** completed
- **Started:** 2026-05-28
- Actions taken:
  - Confirmed working directory is `/Users/akihito/git/mgbdis`.
  - Found planning files were accidentally created one directory above the repository.
  - Moved/re-created source recovery planning files in the `mgbdis` repository root.
  - Recorded known ROM facts from earlier inspection.
  - Created `docs/source_recovery/baseline.md`.
  - Forced a clean RGBDS rebuild and confirmed `Yoshi/game.gb` matches `Yoshi/yoshi.gb` byte-for-byte.
- Files created/modified:
  - `task_plan.md` (created in repository root)
  - `findings.md` (created in repository root)
  - `progress.md` (created in repository root)
  - `docs/source_recovery/baseline.md`

### Phase 2: Memory Map Recovery
- **Status:** in_progress
- **Started:** 2026-05-28
- Actions taken:
  - Created `tools/recovery_refs.py` to summarize WRAM/HRAM references from `bank_000.asm` and `bank_001.asm`.
  - Created `docs/source_recovery/memory_map.md`.
  - Corrected the `VRAM_*` HRAM names in `Yoshi/constants.inc` after tracing `VRAMCopySetup` and `VRAMCopyDMA`.
  - Updated `Yoshi/bank_001.asm` references to use the corrected source/destination/count names.
  - Recovered the option/settings variables at `$C6B2-$C6B5` and active level/speed variables at `$C6B7-$C6B8`.
  - Replaced the misleading `PLAYER_MODE` name with `GAME_TYPE`.
  - Created `docs/source_recovery/options_variables.md`.
  - Verified the rename is behavior-preserving with a byte-identical rebuild.
- Files created/modified:
  - `tools/recovery_refs.py`
  - `docs/source_recovery/memory_map.md`
  - `docs/source_recovery/options_variables.md`
  - `Yoshi/constants.inc`
  - `Yoshi/bank_000.asm`
  - `Yoshi/bank_001.asm`

### Phase 3: Control Flow & State Machine Recovery
- **Status:** in_progress
- **Started:** 2026-05-28
- Actions taken:
  - Traced all direct `GAME_STATE` writes/checks in `bank_000.asm` and `bank_001.asm`.
  - Added `GAME_STATE_*` constants for the seven observed main-loop states.
  - Replaced high-confidence state magic values with constants.
  - Added concise comments to the `MainLoop` dispatcher cases.
  - Created `docs/source_recovery/state_machine.md`.
  - Verified all changes remain byte-identical to the preserved ROM.
- Files created/modified:
  - `docs/source_recovery/state_machine.md`
  - `Yoshi/constants.inc`
  - `Yoshi/bank_000.asm`
  - `Yoshi/bank_001.asm`

### Phase 4: Data & Graphics Recovery
- **Status:** in_progress
- **Started:** 2026-05-28
- Actions taken:
  - Converted Bank 1 `01:$40A0-$42F4` from bogus instructions to `SpriteUpdatePointerTable`, object frame tables, tile-id lists, and layout triples.
  - Preserved compatibility symbols for old fake labels that are still referenced by downstream unconverted data.
  - Created `docs/source_recovery/data_ranges.md`.
  - Verified the conversion remains byte-identical to the preserved ROM.
  - Converted Bank 0 option UI data ranges from bogus instructions to explicit `db` tables:
    - `00:$1D84-$1DBE` option text strings and marker positions.
    - `00:$1E3D-$1E4F` inactive cursor tile triplets.
    - `00:$1E75-$1E89` setting cursor/sprite initialization records.
    - `00:$1F4C-$1F4F` and `00:$2C60-$2C63` option max-value tables.
    - `00:$2026-$203A` highlighted cursor tile triplets.
  - Renamed misleading option UI routines to `DrawOptionTextLabels`, `DrawOptionMarkers`, `DrawOptionMarker`, and `DrawTileTripletList`.
  - Verified the Bank 0 conversion remains byte-identical to the preserved ROM.
  - Converted score/result/continue text data from bogus instructions to explicit `db` strings:
    - `00:$25C3-$25E0` score header strings.
    - `00:$2622-$2663` result two-line text blocks.
    - `00:$2CBC-$2CD6` result header text.
    - `00:$2DE0-$2E2D` restart/result text blocks.
    - `00:$2E38-$2E3B` duplicate `OFF` text.
    - `00:$2E7C-$2EB2` BGM marker strings.
  - Verified the score/result/continue text conversion remains byte-identical to the preserved ROM.
  - Converted the preview/result tile table at `00:$2734-$2853` into `PiecePreviewTextTable` plus six 48-byte three-line entries.
  - Verified the preview table conversion remains byte-identical to the preserved ROM.
  - Converted the countdown digit pattern table at `00:$2FFB-$304A` into ten 8-byte `CountdownDigitPattern*` records.
  - Verified the countdown digit pattern conversion remains byte-identical to the preserved ROM.
  - Reclassified Bank 1 `01:$55E2-$5668` from raw `db` to executable sound setup code as `StartSoundSequence`.
  - Split Bank 1 sound support tables at `01:$5669-$5699` into `SoundWaveDutyData`, `SoundRegisterOffsetTable`, `SoundChannelDisableMaskTable`, `SoundChannelEnableMaskTable`, and `SoundPitchBaseTable`.
  - Corrected the earlier recovery note that treated the full `01:$55E2-$5FE2` range as data.
  - Verified the Bank 1 sound setup conversion remains byte-identical to the preserved ROM.
  - Corrected the `SoundPitchBaseTable` boundary: `$569A` is now `SoundSequenceData_569a`, a real target from the sound index table.
  - Added first-pass internal pointer-target labels to the existing `01:$569A-$5FE2` `SoundSequenceData_*` block.
  - Verified the `$569A-$5FE2` sequence label pass remains byte-identical to the preserved ROM.
  - Converted Bank 1 `01:$5FE3-$7190` from apparent code to explicit music sequence `db` blocks with labels at `$FD/$FE` pointer targets.
  - Verified the `$5FE3-$7190` conversion remains byte-identical to the preserved ROM.
  - Removed the now-unused compatibility `DEF` symbols for old fake sprite/music labels.
  - Verified compatibility-symbol cleanup remains byte-identical to the preserved ROM.
  - Created `docs/source_recovery/sound_engine.md` with first-pass sound command semantics and per-channel state-array notes.
  - Added exact-boundary labels for existing Bank 1 music sequence data at `MusicSequenceData_7191` and `MusicSequenceData_71e4`.
  - Verified the music sequence label additions remain byte-identical to the preserved ROM.
  - Converted Bank 1 `01:$71C1-$71E3` from apparent code to explicit music sequence `db` bytes with internal pointer-target labels.
  - Added a temporary compatibility symbol for the remaining fake `Call_001_71c2` reference in unconverted music data.
  - Verified the `$71C1-$71E3` conversion remains byte-identical to the preserved ROM.
  - Converted the broader Bank 1 music stream `01:$71E4-$77B5` into explicit `db` blocks with internal `$FD/$FE` pointer-target labels.
  - Verified the broader `$71E4-$77B5` music stream conversion remains byte-identical to the preserved ROM.
  - Converted Bank 1 apparent-code music sequence ranges `01:$73B3-$7402` and `01:$77B6-$7805` into explicit `MusicSequenceData_*` `db` blocks.
  - Preserved temporary compatibility symbols for fake references from still-unconverted music streams.
  - Verified the apparent-code music sequence conversion remains byte-identical to the preserved ROM.
  - Converted Bank 1 `01:$7806-$7C01` from apparent instructions to explicit music sequence `db` blocks with labels at local pointer targets.
  - Preserved the adjacent real code island at `01:$7C02-$7C07` and named it `TickBgmPreviewTimer`.
  - Replaced the two Bank 0 `call $7c02` sites with `call TickBgmPreviewTimer`.
  - Added tentative BGM preview timer variables for `$C6C1-$C6C2`.
  - Verified the `$7806-$7C02` boundary recovery remains byte-identical to the preserved ROM.
  - Converted Bank 1 tail data `01:$7C2C-$7FFF` into `SoundIndexTable`, short `SoundSequenceData_*` entries, `WavePatternPointerTable`, and `WavePatternData_*`.
  - Removed fake `Call_001_7f9d` and `jr_001_7*` labels by representing the tail as data.
  - Verified the Bank 1 tail table/data recovery remains byte-identical to the preserved ROM.
  - Added `SOUND_*` WRAM constants for the sound engine work area `$C000-$C0ED`, replacing raw sound-state addresses in Bank 1 sound code and related Bank 0 pause/wait checks.
  - Updated sound-engine documentation to distinguish high-confidence pointer/active-ID/pause/output-mask fields from medium-confidence slide/tempo/envelope fields.
  - Added high-confidence sound ID constants and `SoundIndexTable` alias labels for drop start, falling-piece commit, piece landing, cursor movement, round complete, pause, title BGM, BGM option/preview choices, 2P link BGM choices, confirm, and stop/off.
  - Converted Bank 0 `00:$15FE-$1611` from fake instructions to `LevelFallDelayTable` and restored the real `00:$1612` landing-progress code entry.
  - Converted Bank 0 `00:$18CB-$18E3` from fake instructions to `RoundCompleteStateRemapTable` and `RoundCompleteDelayParamTable`.
  - Named Bank 1 `01:$432F` as `AddScore` and added score accumulator/display constants for `$C61D-$C621`.
  - Replaced Bank 0 direct calls to `$432F`, `$42F5`, `$43F2`, `$445C`, and `$4681` with `AddScore`, `UpdateAnimFrame`, `SetupGameBG`, `StartNextRound`, and `AdvanceEggAnimation` where the target meaning is now known.
  - Converted Bank 1 `01:$442C-$445B` from fake instructions to `FieldColumnTilePatternTable` and preserved `StartNextRound` as the real code entry at `01:$445C`.
  - Named Bank 1 `01:$4681` as `AdvanceEggAnimation`.
  - Converted Bank 0 `00:$22CC-$234B` from fake instructions to `FieldSideDeltaTable` and `FieldRowDeltaTable`, restoring `UpdateFieldTimers` as real code at `00:$234C`.
  - Replaced remaining high-confidence raw cross-bank direct calls with labels, including `WaitVBlank`, `VBlankHandler`, `InitSpriteBuffer`, `InitGameScreen`, `InitPlayfield`, `GameMainUpdate`, `SoundEngine`, `LoadGameBGTiles`, `UpdateFieldTimers`, `SpriteAnimTable`, `DrawTitleLabels`, `ProcessTitleInput`, `ProcessOptionInput`, `UpdateColumn`, and `DrawColumnData`.
  - Added `OAM_DMA_HRAM` for the HRAM DMA routine at `$FF80`, and replaced the VBlank call and setup copy target with that name.
  - Named Bank 1 `01:$4570` as `AdvanceSpriteAnimFrame`.
  - Recovered Bank 0 `00:$33F7` as real code `WaitLinkStartConfirm`, removing a short `db` escape that hid the link-start wait loop.
  - Converted Bank 0 `00:$3839-$3FFF` from fake instructions to `TitleResultTileData0`, `TitleResultTileData1`, and `Bank0TailGraphicsData`.
  - Confirmed there are no remaining raw direct `call $xxxx`, `jp $xxxx`, or `jr $xxxx` operands in `Yoshi/bank_000.asm` and `Yoshi/bank_001.asm`.
  - Added MBC1 ROM bank switch constants for `$2100`, Bank 1, Bank 2, and Bank 3.
  - Replaced all real-code `$2100` bank-switch writes with `MBC1_ROM_BANK_REG`.
  - Created `docs/source_recovery/graphics_loads.md` with the current Bank 2/3 and ROM0 graphics transfer map.
  - Updated `Yoshi/ARCHITECTURE.md` and `docs/source_recovery/memory_map.md` to reflect the named bank register and current graphics-bank understanding.
  - Added `tools/render_gb_tiles.py`, a dependency-free Game Boy 2bpp tile-sheet renderer.
  - Generated PNG tile sheets for the observed Bank 2, Bank 3, and ROM0 graphics load ranges under `docs/source_recovery/tile_sheets/`.
  - Added Bank 3 transfer-start labels for matching, result, high-score, and overlay graphics ranges.
  - Replaced Bank 0 graphics load source immediates with Bank 2 and Bank 3 labels.
  - Corrected two initially misplaced Bank 3 labels after a non-identical rebuild exposed changed `ld hl` immediates.
  - Added sprite/OAM constants for the `$C200` logical object page, `$C400` shadow OAM page, OAM hardware biases, and `UpdateSprites` HRAM temporaries.
  - Replaced high-confidence `UpdateSprites`, `ClearOAM`, `HideAllSprites`, and pause overlay raw OAM addresses with those constants.
  - Created `docs/source_recovery/sprite_oam.md` to document the current logical-object and frame/layout-table format.
  - Traced the first sprite producer path: `UpdateSpriteObject` stages gameplay slots 1-4 through `$C68C-$C695`, while slot 0 and slots 9-13 are managed by separate UI/gameplay setup paths.
  - Split the Bank 1 sprite update payload into `SpriteFrameTable_*`, `SpriteTileList_*`, and `SpriteLayout_*` labels.
  - Named confirmed sprite object types `$01-$05` and their corresponding frame tables where call-site evidence was strong.
- Files created/modified:
  - `docs/source_recovery/data_ranges.md`
  - `docs/source_recovery/sound_engine.md`
  - `docs/source_recovery/graphics_loads.md`
  - `docs/source_recovery/sprite_oam.md`
  - `docs/source_recovery/tile_sheets/`
  - `docs/source_recovery/memory_map.md`
  - `tools/render_gb_tiles.py`
  - `Yoshi/ARCHITECTURE.md`
  - `Yoshi/constants.inc`
  - `Yoshi/bank_001.asm`
  - `Yoshi/bank_000.asm`

## Test Results
| Test | Input | Expected | Actual | Status |
|------|-------|----------|--------|--------|
| RGBDS rebuild | `make -B` in `Yoshi/` | build succeeds | build succeeds | pass |
| SHA-256 comparison | `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` | same hash | both `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` | pass |
| Binary comparison | `cmp -s Yoshi/yoshi.gb Yoshi/game.gb` | exit `0` | exit `0` | pass |
| State constantization rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Option variable rename rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Sprite data conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 0 option UI data conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 0 score/result text conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 0 preview table conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 0 countdown digit table conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 sound setup conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 `$569A-$5FE2` sequence label rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 `$5FE3-$7190` music stream conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 compatibility-symbol cleanup rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 music sequence label rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 `$71C1-$71E3` music sequence conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 `$71E4-$77B5` music stream conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 apparent-code music sequence conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 `$7806-$7C02` boundary recovery rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 tail sound table/data recovery rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Sound WRAM constantization rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Confirmed sound ID constantization rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 0 level fall-delay table recovery rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 0 round-complete table recovery rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0` | pass |
| Bank 1 score/field-table/round-entry label rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Bank 0 field delta and tail graphics recovery rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| MBC1 bank constantization rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Graphics tile rendering | `python3 tools/render_gb_tiles.py --preset yoshi-graphics` | PNG sheets generated | 18 tile sheets and `README.md` generated under `docs/source_recovery/tile_sheets/` | pass |
| Bank 2/3 graphics label rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Sprite/OAM constantization rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Sprite object producer constantization rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Sprite frame/tile/layout table split rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Sprite object type naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Raw direct branch scan | `rg -n 'call \\$|jp \\$|jr \\$' Yoshi/bank_000.asm Yoshi/bank_001.asm` | no matches | no matches | pass |

## Error Log
| Timestamp | Error | Attempt | Resolution |
|-----------|-------|---------|------------|
| 2026-05-28 | Planning files placed in parent directory | 1 | Re-created under `mgbdis/` and removed parent copies. |
| 2026-05-28 | First `VRAM_*` rename changed output bytes at `$4B45/$4B48` | 1 | Corrected `VRAMCopyDMA` destination pointer stores to `$FFB1/$FFB2`; `cmp` returned exit `0`. |
| 2026-05-28 | First `FieldRowDeltaTable` split made ROM0 one byte too large, then produced byte differences | 1 | Rechecked the exact source bytes with `xxd`; corrected the table to exact `00:$230F-$234B` length/content and restored `UpdateFieldTimers` at `00:$234C`. |
| 2026-05-28 | Initial Bank 3 graphics labels for `$5C00` and `$6AB0` landed at repeated-looking rows and changed two `ld hl` operands | 1 | Address-counted `bank_003.asm` by 16-byte tile rows, moved labels to exact source offsets, then restored byte-identical output. |

## 5-Question Reboot Check
| Question | Answer |
|----------|--------|
| Where am I? | Phase 2 memory-map, Phase 3 state-machine, and Phase 4 data recovery |
| Where am I going? | More code/data separation, graphics/data maps, sound/music data recovery, gameplay algorithms |
| What's the goal? | Recover the lost Game Boy YOSSY NO TAMAGO source as maintainable, buildable RGBDS assembly |
| What have I learned? | See findings.md |
| What have I done? | Captured baseline facts, verified byte-identical rebuild, added recovery docs/tooling, corrected VRAM transfer variables, named the main `GAME_STATE` values, recovered core option/game-type variables, converted and structured the first Bank 1 sprite data range, converted Bank 0 option UI, score/result/preview text, countdown digit tables, the level fall-delay table, round-complete tables, field delta tables, and ROM0 tail graphics data, restored the Bank 1 sound setup entry at `$55E2` as code, labeled and converted the contiguous Bank 1 sound/music stream from `$569A` through `$7C01` to data, separated the real `$7C02` helper from the surrounding music stream, recovered the `$7C2C-$7FFF` sound index/wave/tail sequence data, named the sound WRAM structure from `$C000-$C0ED` with `SOUND_*` constants, named high-confidence sound IDs from call-site evidence, named the score add/display routine and score WRAM, converted the `$442C` field-column tile table, named the next-round, sprite-animation, egg-animation, field-timer, and link-start helpers, removed remaining raw direct call/jump operands from real code paths, added the first rendered graphics evidence pass with Bank 2/3 transfer-start labels, documented the first-pass sprite/OAM object expansion format, traced the first sprite object producer/staging path, and named confirmed sprite object types `$01-$05` |
