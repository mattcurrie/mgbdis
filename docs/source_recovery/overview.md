# Source Recovery Overview

This document is the entry point for the current Game Boy YOSSY NO TAMAGO
source recovery state. It summarizes what is evidence-backed, which evidence
limits remain documented, and which invariants must stay true if the source is
refined later.

## Baseline

`Yoshi/yoshi.gb` is the preserved reference ROM. Current source edits are
behavior-preserving only when the rebuilt `Yoshi/game.gb` remains byte-identical
to that ROM.

The recovery gate is:

```text
tools/verify_yoshi_build.sh
```

That script runs the RGBDS rebuild, compares `game.gb` against `yoshi.gb`, and
checks ROM size/header facts plus generated artifact cleanliness. See
`baseline.md` for the exact checksum, ROM header, bank layout, and verifier
contract.

## Current Shape

The source is split into four ROM banks:

| Bank | File | Current role |
|------|------|--------------|
| 0 | `Yoshi/bank_000.asm` | Fixed bank: entry, interrupts, main loop, game state, gameplay/UI logic, table consumers. |
| 1 | `Yoshi/bank_001.asm` | Normal switch bank: VBlank, sprite expansion, sound/link helpers, shared runtime data. |
| 2 | `Yoshi/bank_002.asm` | Graphics/tile data copied into VRAM. |
| 3 | `Yoshi/bank_003.asm` | Result, matching, high-score, and other graphics/tile data copied into VRAM. |

Bank 1 is the normal active switch bank during LCD-on execution. Banks 2 and 3
are selected temporarily for controlled graphics loads and then Bank 1 is
restored.

## Recovered Areas

High-confidence recovery areas already have dedicated notes:

| Area | Primary notes |
|------|---------------|
| Build and ROM identity | `baseline.md` |
| WRAM/HRAM names and confidence | `memory_map.md`, `confidence_and_open_questions.md` |
| Code/data boundaries and recovered data tables | `data_ranges.md` |
| Sprite/OAM object model | `sprite_oam.md` |
| Gameplay board/fall/drop state | `board_layout.md`, `column_state.md`, `drop_animation_state.md`, `fall_timing.md` |
| Options/title/menu state | `options_variables.md`, `title_menu.md`, `settings_blink_state.md` |
| Result records and timers | `result_records.md`, `egg_counter.md` |
| Link protocol/state | `link_state.md`, `Yoshi/SERIAL_PROTOCOL.md` |
| Sound engine | `sound_engine.md` |
| Graphics loads and tile sheets | `graphics_loads.md`, `tile_sheets/README.md` |
| Optional future refinement notes | `next_work_checklist.md` |

## Confidence Policy

Names and comments should remain tied to evidence:

- High confidence: direct code behavior, table contract, or build evidence
  proves the name.
- Medium confidence: strong local context supports the name, but it may still
  be refined.
- Low confidence: useful hypothesis only; avoid baking it into broad comments.

When a byte has only write patterns or one narrow consumer, keep it unresolved
until there is an independent producer/consumer relationship.

## Completion Status

The 541-item recovery checklist is complete for this pass. The rebuilt
`Yoshi/game.gb` is byte-identical to `Yoshi/yoshi.gb`, and the source no longer
has raw Bank 0/1 WRAM references, raw direct branch targets, generated local
labels, or anonymous relative branch labels in the audited paths.

The most valuable optional future refinements are:

- Map any remaining player-visible piece payload identities if independent
  evidence appears.
- Refine medium-confidence sound channel fields by decoding more sequence
  examples.
- Compare ambiguous behavior with user memory when static analysis leaves more
  than one plausible interpretation.

Use `next_work_checklist.md` as optional refinement guidance, not as required
remaining work for the completed checklist.

## Handoff Rule

Every chunk should leave the repository in a rebuildable state. Before commit,
run `tools/verify_yoshi_build.sh`; if it does not pass, either fix the source or
do not treat the chunk as recovered source.
