# Confidence And Open Questions

This note is a handoff summary for confidence levels and unresolved questions.
It does not replace the detailed subsystem notes; use it to decide what should
be trusted, what may be refined, and what should stay unnamed until stronger
evidence appears.
These unresolved questions are evidence limits for optional future refinement;
they are not remaining checklist work for the completed recovery pass.

## Confidence Levels

| Level | Use it for | Current examples |
|-------|------------|------------------|
| High | Direct code behavior, table contracts, or build evidence prove the name. | ROM/bank constants, VRAM copy variables, `BG_MAP_SHADOW`, `SPRITE_OBJECTS`, score digits, option variables, result records, link send queues, countdown digit buffers. |
| Medium | Local evidence is strong, but the exact role may still be refined. | `SCREEN_STATE`, `ANIM_FRAME`, some result tilemap origins, `LINK_FIELD_EVENT_PAYLOAD`, several sound channel fields. |
| Low | The name is only a useful hypothesis or a write-only/reset pattern. | `UNRESOLVED_LANDING_RESET_BYTE_0`, `UNRESOLVED_LANDING_RESET_BYTE_1`, `UNRESOLVED_LANDING_RESET_TIMER`, `SCORE_PRESERVED_UNUSED_BYTE`, `SCORE_UNUSED_TILE_BASE_*`, `TITLE_RESET_UNUSED_HRAM_FLAG`, `TITLE_PLAYER_MARKER_UNUSED_DELAY`, `EGG_COUNT_UNUSED_BYTE`, `BGM_PREVIEW_UNUSED_PERIOD`, `LINK_UNUSED_STAGING_BYTE`, `DROP_ANIM_UNUSED_GRID_ROW_TMP`. |

Do not promote a low-confidence byte just because it is near a recovered
structure. Promote it only after an independent consumer or a clear table
contract is found.

## Trusted Foundations

- `Yoshi/yoshi.gb` is the preserved reference ROM, and
  `tools/verify_yoshi_build.sh` is the current behavior-preserving gate.
- The four-bank ROM layout and MBC1 bank register are high confidence.
- Bank 1 is the normal active switch bank during LCD-on execution; Banks 2 and
  3 are graphics/data banks selected temporarily by controlled load paths.
- Several former fake-code regions are now explicit data ranges. The current
  authoritative list is `data_ranges.md`.
- WRAM/HRAM names should be checked against `memory_map.md` before broad
  comments are added.

## Open Questions

| Area | Question | Current best evidence |
|------|----------|-----------------------|
| Piece payloads | What exact game pieces or states do all payload values represent? | `BOARD_SCAN_TRIGGER_PAYLOAD` and `BOARD_SCAN_TARGET_PAYLOAD` are named by scan behavior only; broader piece semantics remain open. |
| Landing scan state | What are `UNRESOLVED_LANDING_RESET_BYTE_0`, `UNRESOLVED_LANDING_RESET_BYTE_1`, `UNRESOLVED_LANDING_SCAN_COUNTER`, and `UNRESOLVED_LANDING_RESET_TIMER` semantically? | Reset/write/decrement patterns are real, but only the scan counter has a confirmed read/write role in scan/landing timing. A follow-up all-source and recent-history search found no hidden producer for these four bytes. |
| Sprite object slots | Are there any independent consumers for slot-local `+$01`, the BGM-cursor-only `+$03`, or the fast-fall-clamp-only `+$0F`? | `UpdateSprites` skips `+$01`; `ApplySoundVisualUpdateCommand` toggles `+$03` only for option BGM cursor frames; `ClampGameplayObjectFastFallLoop` writes `+$0F`, but no independent consumer has been confirmed. |
| Sprite object type `$07` and high-bit object types | Is `SPRITE_OBJECT_TYPE_RESERVED_7` ever produced, and are there semantic high-bit object types? | The `$07` frame-table entry exists and draws two tile `$E0` sprites, but no producer is confirmed. `UpdateSprites` saves bit `$80` for inherited OAM attributes; valid `$81-$87` values then share the `$01-$07` frame-table entries because `dec` + `sla` drops bit 7 from the table offset. No high-bit producer is confirmed. |
| Sound commands | What are the full command semantics and channel roles in the recovered music streams? | Sound state and index tables are structured, but medium-confidence `SOUND_CH_*` names need more sequence decoding. |
| Bank 3 graphics | Which exact screen regions do remaining Bank 3 tile ranges represent? | Load paths and VRAM destinations are documented, but several ranges still need visual/screen-role decoding. |
| User testimony | Which ambiguous behaviors match original implementation intent? | Static analysis can show behavior, but not always why the code was structured that way. Compare with user memory where available. |

## Naming Rule

Prefer narrow names that describe the proven behavior over broad names that
guess intent. For example, `BOARD_SCAN_TARGET_PAYLOAD` is acceptable because it
describes the observed scan target; a concrete piece-name label should wait
until the payload's player-visible meaning is proven.
