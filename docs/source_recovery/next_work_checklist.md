# Source Recovery Next-Work Checklist

This checklist records the next useful recovery chunks after the current
documentation checkpoint. It is intentionally evidence-first: each source edit
should make the recovered source more maintainable without changing the ROM.

## Verification Habit

- Run `tools/verify_yoshi_build.sh` before every commit.
- Treat `Yoshi/yoshi.gb` as the preserved baseline.
- Keep `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb` unless there is an
  explicit, separately documented reason to change behavior.
- Commit only the intended source and documentation files for the chunk.
- Leave unrelated local files, including `CLAUDE.md`, untouched.

## Immediate Recovery Chunks

### Board Cell And Piece Representation

- Trace `BOARD_DATA` as paired or interleaved bytes before assigning stronger
  cell-field names.
- Follow `BOARD_SCAN_TRIGGER_PAYLOAD` and `BOARD_SCAN_TARGET_PAYLOAD` from
  producer to visible piece effect before broadening comments.
- Keep `$C69D`, `$C6AE`, `$C6BF`, and `$C6C0` unresolved until there is
  independent read/write evidence beyond the current landing/scan context.
- Cross-check any proposed board-field name against `board_layout.md`,
  `column_state.md`, `drop_animation_state.md`, and `fall_timing.md`.

### Gameplay Routine Naming

- Name drop, rotation, match, clear, scoring, level, and game-over routines only
  when call sites and state changes agree.
- Prefer narrow names tied to proven behavior over broad game-design terms.
- Keep comments local and confidence-bounded when a routine has more than one
  plausible role.

### Sprite Object Slots

- Trace slot-local fields `+$01`, `+$03`, and `+$0F` across the logical sprite
  page and OAM expansion path.
- Decode object types `$06`, `$07`, and high-bit object types from their setup
  tables and render/update consumers.
- Update `sprite_oam.md` only when a field role is visible in both a producer
  and a consumer.

### Sound And Music

- Decode more sequence commands from actual stream examples before renaming
  medium-confidence `SOUND_CH_*` fields.
- Tie channel roles to command behavior, not only byte offsets.
- Keep sound call-site aliases only where the surrounding game state proves the
  effect role.

### Graphics And Data Boundaries

- Identify Bank 3 screen/tile roles from load destinations and visible usage.
- Continue converting repeated table and text blocks from fake code into named
  data ranges.
- Preserve exact bytes and labels around any ambiguous code/data boundary until
  the verifier proves the split is behavior-preserving.

### User Memory Comparison

- Use developer memory to prioritize and confirm ambiguous behavior.
- Do not let memory override binary evidence when the code shows a different
  behavior.
- Record any confirmed historical fact separately from static code facts.

## Chunk Checklist

For each future chunk:

1. Inspect `git status --short --branch` and the relevant notes.
2. Read all references before editing.
3. Make one behavior-preserving symbolic, data-boundary, or documentation
   improvement.
4. Update the relevant source recovery notes and `task_plan.md` if the chunk
   changes plan status.
5. Run `tools/verify_yoshi_build.sh`.
6. Review `git diff --check` and staged files.
7. Commit only the intended files.
8. Leave the final status clean except for unrelated user-local files.
