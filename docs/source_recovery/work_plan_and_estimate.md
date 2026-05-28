# YOSSY NO TAMAGO Source Recovery Work Plan And Estimate

This document records what has been done, what remains, and why the time
estimate is large. The goal is source recovery, not a cosmetic rename pass:
each accepted change must remain byte-identical to `Yoshi/yoshi.gb`.

## Current Status

- Branch: `yoshi-disassembly-step6`
- Latest completed commit at this checkpoint: `db28094 Name result record state`
- Worktree caveat: `CLAUDE.md` is untracked and intentionally ignored.
- Current invariant: `Yoshi/game.gb` rebuilds byte-identical to
  `Yoshi/yoshi.gb`.
- Current ROM SHA-256 for both files:
  `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
- Current raw direct branch scan:
  `rg -n 'call \$|jp \$|jr \$' Yoshi/bank_000.asm Yoshi/bank_001.asm`
  returns no matches.
- Current raw WRAM-style references in `bank_000.asm` / `bank_001.asm`:
  145 occurrences, 87 distinct `$Cxxx` addresses. Many are tilemap offsets or
  already understood structures, but each still needs evidence before naming.

## Completed Work

### Baseline And Build

- Established `Yoshi/yoshi.gb` as the behavioral baseline.
- Confirmed the ROM is 64KB, MBC1, with four 16KB banks.
- Confirmed RGBDS rebuild produces byte-identical `Yoshi/game.gb`.
- Added persistent planning files:
  - `task_plan.md`
  - `findings.md`
  - `progress.md`
- Added baseline and memory-map notes under `docs/source_recovery/`.

### Bank, State, And Runtime Structure

- Named the MBC1 bank register and bank IDs:
  `MBC1_ROM_BANK_REG`, `ROM_BANK_MAIN_CODE`,
  `ROM_BANK_GRAPHICS_0`, `ROM_BANK_GRAPHICS_1`.
- Documented Bank 1 as the normal active code bank and Banks 2/3 as graphics
  banks loaded temporarily.
- Named the seven observed `GAME_STATE` values and documented the main state
  machine.
- Recovered the pre-play/title menu flow and link-start wait path.

### Data/Code Separation

- Converted many fake-code ranges into explicit data blocks while preserving
  exact bytes:
  - Bank 0 option UI strings and marker tables.
  - Bank 0 preview/result/countdown text and digit tables.
  - Bank 0 game-turn parameter table.
  - Bank 0 matching/result OAM templates and scoring tables.
  - Bank 0 round-complete tables and field animation delta tables.
  - Bank 0 tail graphics.
  - Bank 1 sprite frame/tile/layout tables.
  - Bank 1 sound setup support tables.
  - Bank 1 music sequence streams and tail sound/wave tables.
- Verified after each conversion with byte-identical rebuilds.

### Memory Map And WRAM/HRAM Recovery

- Named and documented key HRAM:
  - OAM DMA routine address.
  - VRAM copy queue fields.
  - unused secondary VRAM-copy slot.
  - joypad, VBlank, serial, and game-state bytes where evidence supports it.
- Named and documented many WRAM structures:
  - sound engine work RAM `$C000-$C0ED`
  - score BCD/display digits
  - logical sprite object page `$C200-$C2FF`
  - shadow OAM `$C400-$C49F`
  - BG map shadow `$C4A0-$C607`
  - options and active game settings
  - piece display/shuffle state
  - falling-piece timing state
  - column top-row and drop cursor animation state
  - field animation slot cursors/flags/timers
  - elapsed timers
  - egg counter and egg text animation state
  - link settings, link send queue, result handshake state
  - countdown digit buffers
  - result records and reset-persistent magic

### Graphics And Sound

- Added a dependency-free GB 2bpp tile renderer:
  `tools/render_gb_tiles.py`.
- Generated first-pass rendered tile-sheet evidence under
  `docs/source_recovery/tile_sheets/`.
- Documented graphics load ranges and VRAM destinations.
- Recovered first-pass sound/music command semantics and many `PlaySound`
  call-site names.

### Recent Completed Chunks

- `76f3000 Name falling piece timing state`
- `12aabd2 Name piece display state array`
- `6c9fab5 Name piece display shuffle state`
- `6735114 Name piece display count and column seed`
- `71edf6c Name fall acceleration timer`
- `a848747 Name result flow flag`
- `14a83f6 Name queued round result state`
- `74dda5b Name peer result code`
- `e111ecb Name link send drop lock`
- `400d34b Name elapsed timer state`
- `d81195a Name result outcome flags`
- `549caf5 Name field column tile pattern index`
- `674607a Name egg text animation state`
- `14ad063 Name round complete parameter index`
- `f2efc13 Name round complete tile origin`
- `83e3437 Name link result mark counts`
- `5f8866e Name piece display remaining counter`
- `2ff999c Name progression level`
- `f84ddff Name tilemap shadow buffer`
- `db28094 Name result record state`

## Remaining Work

### Immediate Next Chunks

- Continue classifying `$C69D`, `$C6AE`, `$C6BF`, and `$C6C0` around falling,
  display-state, and game-over flow.
- Continue replacing raw tilemap offsets with named screen-region constants only
  where a repeated layout role is clear.
- Keep `$C620`, `$C628`, `$C629`, and `$C672` unresolved until a consumer is
  found. They are touched around score/init code, but the current scan shows no
  independent read of the `$C628/$C629/$C672` chain and only preserve/restore
  behavior for `$C620`.

### Medium-Term Work

- Recover board layout and piece representation more precisely.
- Name drop, rotation, match, clear, remaining score, level, and game-over
  routines.
- Expand comments only after variable/routine meaning is evidence-backed.
- Continue turning repeated table and text blocks into named data ranges.
- Improve docs so each major subsystem has:
  - variable map
  - routine map
  - data tables
  - unresolved questions

### Longer-Term Work

- Add automated verification scripts for:
  - `make -B`
  - `cmp -s yoshi.gb game.gb`
  - expected SHA-256
  - generated artifact cleanliness
  - raw direct branch scan
- Build a higher-level architecture overview of the recovered source.
- Produce subsystem-level handoff notes for gameplay, link, sound, graphics,
  result records, and rendering.
- Compare uncertain behavior with user memory when static analysis leaves more
  than one plausible interpretation.

## Time Estimate

### Checkpoint Estimate

These estimates assume the same quality bar used so far: every source change is
validated byte-identical and committed as an evidence-backed chunk.

| Scope | Estimated Time | Result |
|-------|----------------|--------|
| Close one simple naming chunk | 10-30 minutes | One small set of existing raw references replaced and committed. |
| One evidence-backed WRAM structure | 30-90 minutes | Names, source replacements, memory-map/docs update, rebuild, commit. |
| One data/code boundary correction | 1-3 hours | Exact range split, labels, docs, byte-identical rebuild, commit. |
| Remaining high-confidence cleanup pass | 20-40 hours | Most obvious raw refs and docs inconsistencies reduced. |
| Practical maintainable recovery | 100-200 hours total work | Readable, buildable, subsystem-documented source, still with uncertainty notes. |
| Original-source-equivalent recovery | Not bounded | Without the original source, exact symbol names, comments, and structure cannot be proven. |

### Estimate Rationale

- The user-observed session time is already about 6 hours for a set of small,
  carefully verified recovery chunks.
- Since the current checkpoint, the repository has 42 commits in this recovery
  session. That is good throughput, but many commits are intentionally narrow:
  each one preserves behavior and avoids speculative broad rewrites.
- Current scan still shows 145 raw `$Cxxx` occurrences and 87 distinct raw WRAM
  addresses in `bank_000.asm` / `bank_001.asm`. Not all require unique names,
  but each remaining candidate must be classified as one of:
  - real state variable
  - structure field
  - tilemap offset
  - shadow OAM offset
  - temporary scratch
  - leftover data/code classification issue
- The raw direct branch problem is currently solved, so remaining work is less
  about obvious `call $xxxx` labels and more about semantic recovery, which is
  slower.
- Each accepted chunk includes fixed overhead:
  - read all references
  - inspect surrounding code
  - decide confidence and name
  - edit source with labels/constants
  - update docs
  - run `git diff --check`
  - run `make -B`
  - verify `cmp -s yoshi.gb game.gb`
  - verify SHA-256
  - confirm generated artifacts are unchanged
  - commit only the intended files
- Gameplay algorithm recovery is the slowest part. Variables can often be named
  locally, but proving board semantics, match rules, and result flow requires
  following multi-routine behavior across Bank 0 and Bank 1.
- “Perfect source” has no finite estimate because the original source is gone.
  The attainable target is a behavior-preserving, maintainable source with clear
  evidence and confidence levels.

## Operating Rules Going Forward

- Keep commits small and reversible.
- Preserve byte-identical output for every recovery chunk.
- Do not rename uncertain values as facts; document uncertainty explicitly.
- Prefer high-confidence structures over broad speculative comments.
- Leave unrelated/untracked user files such as `CLAUDE.md` untouched.
