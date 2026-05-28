# Task Plan: YOSSY NO TAMAGO Source Recovery

## Goal
Recover the lost Game Boy YOSSY NO TAMAGO source as a maintainable, buildable RGBDS assembly codebase whose labels, variables, data blocks, and comments reflect the original program structure as accurately as evidence allows.

## Current Phase
Phases 2-4

## Work Inventory And Estimate

The current completed-work list, remaining-work list, and time estimate are
recorded in `docs/source_recovery/work_plan_and_estimate.md`.

## Phases

### Phase 1: Baseline & Evidence Inventory
- [x] Preserve the current ROM, symbols, and generated assembly as the baseline
- [x] Identify which files are original artifacts, generated artifacts, and analysis notes
- [x] Record known facts from ROM headers, bank layout, and user testimony
- [x] Document initial findings in findings.md
- **Status:** completed

### Phase 2: Memory Map Recovery
- [x] Build initial WRAM/HRAM read-write index
- [x] Name first high-confidence VRAM transfer variables
- [x] Document uncertain variables with evidence and confidence
- [x] Update constants/includes without changing behavior
- [x] Recover sound engine WRAM constants for `$C000-$C0ED`
- [x] Name BG map shadow buffer `$C4A0-$C607`
- [x] Name result record state `$C709-$C75C`
- **Status:** in_progress

### Phase 3: Control Flow & State Machine Recovery
- [x] Name all currently observed states in GAME_STATE
- [ ] Trace title, demo/attract, gameplay, round end, options, and 2P paths
- [x] Rename the state `$05/$06` 1P/2P pre-play dispatch and loop routines
- [x] Rename the state `$01` title menu frame loop
- [ ] Split code/data misclassifications found in bank_000.asm and bank_001.asm
- [ ] Verify bank assumptions around interrupt-sensitive paths
- **Status:** in_progress

### Phase 4: Data & Graphics Recovery
- [ ] Map Bank 2/3 tile blocks to VRAM destinations and screens
- [x] Build initial cross-reference table for Bank 2/3 graphics loads
- [x] Add a repeatable GB 2bpp tile renderer and first rendered tile-sheet evidence
- [x] Replace Bank 0 graphics-load source immediates with Bank 2/3 data labels
- [ ] Identify tilemaps, OAM templates, animation tables, and score/text data
- [x] Document first-pass `$C200` logical sprite object and `$C400` shadow OAM format
- [x] Trace first-pass `$C200` sprite object producer/staging path
- [x] Split Bank 1 sprite frame data into frame tables, tile lists, and layouts
- [x] Name confirmed sprite object types `$01-$05`
- [x] Convert Bank 1 sprite/title tile strings at `$462B` and `$46ED`
- [x] Name title player selection marker blink WRAM
- [x] Convert first obvious data blob from bogus instructions to db/dw labels
- [x] Convert Bank 0 option UI strings, marker coordinates, cursor tile lists, and option bound tables
- [x] Convert Bank 0 2P settings limit and round palette byte tables
- [x] Convert Bank 0 score/result/continue text strings and marker strings
- [x] Convert Bank 0 preview/result tile string table
- [x] Convert Bank 0 countdown digit pattern table
- [x] Convert Bank 0 level fall-delay table at `$15FE` and restore the `$1612` code boundary
- [x] Convert Bank 0 game-turn parameter table head at `$0B8D` and name its index/timer/delay bytes
- [x] Convert Bank 0 matching OAM, score bonus, and tile-base tables at `$117C-$11EF`
- [x] Convert Bank 0 round-complete tables at `$18CB` and `$18D2`
- [x] Convert Bank 0 field delta tables at `$22CC` and `$230F`
- [x] Name field animation cursors, active flags, and column timers at `$C6C3-$C6CE`
- [x] Name drop-input animation active/timer/column/cascade state at `$C75D-$C774`
- [x] Name column top-row array and drop cursor animation state at `$C66A-$C670`
- [x] Name egg counter digits and level-display tick divider at `$C6D1-$C6D5`
- [x] Name 2P selected settings, peer settings, and link send queue at `$C6EB-$C700`
- [x] Name column blink state and result rank position at `$C7A4-$C7AD`
- [x] Name countdown digit buffers and blit state at `$C7AE-$C7CF`
- [x] Name 2P settings cursor and shared settings/result blink timer at `$C6F0-$C6F2`
- [x] Confirm `$FFB3-$FFB7` as an unused secondary VRAM-copy slot
- [x] Convert Bank 0 tail graphics data at `$3839-$3FFF`
- [x] Convert Bank 1 field-column tile pattern table at `$442C` and restore the `$445C` code boundary
- [x] Reclassify Bank 1 `$55E2` sound setup entry as code and split immediate sound support tables
- [x] Add internal pointer labels to Bank 1 sound sequence block at `$569A`
- [x] Convert Bank 1 fake-code music sequence range at `$5FE3`
- [x] Add exact-boundary labels for Bank 1 music sequence data at `$7191` and `$71E4`
- [x] Convert Bank 1 fake-code music sequence range at `$71C1`
- [x] Convert the broader Bank 1 music stream from `$71E4` through `$77B5`
- [x] Convert Bank 1 fake-code music sequence ranges at `$73B3` and `$77B6`
- [x] Convert Bank 1 fake-code music sequence range at `$7806` while preserving the real `$7C02` helper
- [x] Recover Bank 1 sound index table, wave pattern pointer table, and tail sound sequences
- [x] Document first-pass Bank 1 sound/music command semantics
- [x] Replace high-confidence sound-engine raw addresses with `SOUND_*` constants
- [x] Name high-confidence sound IDs from `PlaySound` call-site evidence
- [ ] Continue classifying remaining effect IDs once gameplay/link/result routines are better named
- [x] Build cross-reference tables for graphics loads
- **Status:** in_progress

### Phase 5: Gameplay Algorithm Recovery
- [x] Recover first-pass board column-block layout
- [ ] Recover remaining piece representation semantics inside board cells
- [x] Recover first-pass drop-input column swap animation state
- [x] Recover first-pass column top-row state and drop cursor animation state
- [x] Name the high-confidence score addition/display routine at Bank 1 `$432F`
- [x] Name the next-round and egg-animation helpers at Bank 1 `$445C` and `$4681`
- [x] Name high-confidence field timer, level display, OAM DMA HRAM, and link-start wait helpers
- [ ] Name drop, rotation, match, clear, remaining scoring, level, and game-over routines
- [x] Investigate remaining score-adjacent state `$C620/$C628/$C629/$C672`
- [ ] Revisit `$C620/$C628/$C629/$C672` only after finding an independent consumer
- [x] Name sprite object delay reload byte `$C66E`
- [x] Name piece display blink timer `$C6AF`
- [x] Name piece display forced-state flags `$C6AD/$C6F7/$C6F8`
- [x] Document unresolved landing/scan bytes `$C69D/$C6AE/$C6BF/$C6C0`
- [ ] Revisit `$C69D/$C6AE/$C6BF/$C6C0` only after finding stronger producer/consumer evidence
- [x] Name repeated result main panel tilemap origin `$C546`
- [x] Name result main panel right-edge tilemap origin `$C54C`
- [x] Name result score value tilemap origin `$C5D6`
- [x] Name result score label tilemap origin `$C5D1`
- [x] Name result timer label/value tilemap origins `$C5E5/$C5EA`
- [x] Correct level display digit labels `$C6CF/$C6D0/$C6D1`
- [x] Name result level/speed tilemap origins `$C509/$C50F-$C512`
- [x] Name title player marker row coordinates and tile IDs
- [x] Name title label row coordinates `$0F06/$1006`
- [x] Name option text label row coordinates
- [x] Name option marker coordinates and tile IDs
- [x] Name option cursor decoration triplets and tile IDs
- [x] Name gameplay cursor/drop input masks and fast-fall clamp constants
- [x] Name board fall-end row boundary
- [x] Apply board fall-end row boundary consistently in gameplay setup/update
- [x] Name board scan trigger/target payload constants
- [x] Name board scan animation/link/sound constants
- [x] Add board scan sound table alias
- [x] Alias board scan sound range
- [ ] Compare inferred behavior with user memory where available
- [ ] Add comments only where the code evidence supports them
- **Status:** pending

### Phase 6: Build & Regression Verification
- [x] Confirm RGBDS build reproduces yoshi.gb or document exact differences
- [x] Add scripts/checks for checksum, size, header, and binary comparison
- [ ] Keep source edits behavior-preserving
- **Status:** pending

### Phase 7: Documentation & Handoff
- [x] Write a source recovery overview
- [x] Summarize confidence levels and unresolved questions
- [x] Provide a next-work checklist
- **Status:** completed

## Key Questions
1. Which labels/comments are already trusted, and which were guessed by prior analysis?
2. Where is the boundary between real code and data currently mis-disassembled as code?
3. Which WRAM/HRAM variables are central enough to unlock most function names?
4. Can the current source rebuild byte-for-byte to the preserved ROM?
5. Which facts can user testimony confirm that static analysis cannot?

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| Treat yoshi.gb as the preserved baseline | The original source is lost; binary behavior is the strongest artifact. |
| Work incrementally and behavior-preserving | Source recovery loses value if edits change the ROM without intent. |
| Prioritize WRAM/HRAM naming before broad commenting | Variable meaning will make later control-flow naming more reliable. |
| Keep uncertain comments marked by confidence | Avoid turning guesses into false history. |

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| Planning files were initially created one directory above `mgbdis` | 1 | Moved the plan files into `mgbdis/` and removed misplaced parent copies. |
| First VRAM transfer rename shifted two assembled HRAM operands | 1 | Binary diff isolated offsets `$4B45/$4B48`; corrected `VRAMCopyDMA` to store updated destination low/high at `$FFB1/$FFB2`, restoring byte-identical output. |
| Two Bank 3 transfer labels were initially inserted at repeated-looking `db` rows instead of exact source offsets | 1 | Address-counted `bank_003.asm` by 16-byte tile rows, moved the labels to `$5C00` and `$6AB0`, and restored byte-identical output. |
| Initial `$C5D1` label patch used stale `task_plan.md` context | 1 | Re-read the live plan section and reapplied the edit with the current surrounding lines. |

## Notes
- User testimony: the user programmed the GB version with Yuji Shinkai; source was lost in an accident.
- Historical constraint: GB version was originally 32KB-oriented, then Nintendo allowed 64KB to shorten development.
- Current ROM is 64KB, MBC1, 4 banks of 16KB.
- User explicitly wants a high-fidelity source recovery effort, not a quick or minimal cleanup.
