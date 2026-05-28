# Confidence And Open Questions

This note is a handoff summary for confidence levels and unresolved questions.
It does not replace the detailed subsystem notes; use it to decide what should
be trusted, what may be refined, and what should stay unnamed until stronger
evidence appears.

## Confidence Levels

| Level | Use it for | Current examples |
|-------|------------|------------------|
| High | Direct code behavior, table contracts, or build evidence prove the name. | ROM/bank constants, VRAM copy variables, `BG_MAP_SHADOW`, `SPRITE_OBJECTS`, score digits, option variables, result records, link send queues, countdown digit buffers. |
| Medium | Local evidence is strong, but the exact role may still be refined. | `BOARD_DATA` cell layout, `SCREEN_STATE`, `ANIM_FRAME`, some result tilemap origins, `LINK_FIELD_EVENT_PAYLOAD`, several sound channel fields. |
| Low | The name is only a useful hypothesis or a write-only/reset pattern. | `$C69D`, `$C6AE`, `$C6C0`, `EGG_COUNT_RESERVED`, `BGM_PREVIEW_PERIOD`, `LINK_STAGING_BYTE`, `DROP_ANIM_GRID_ROW_TMP`. |

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
| Board cells | What do the paired/interleaved bytes inside each 16-byte column block mean? | `BOARD_DATA` is four 16-byte columns. Visible rows are read from odd offsets, while fall scanning indexes by row/fall position. |
| Piece payloads | What exact game pieces or states do all payload values represent? | `BOARD_SCAN_TRIGGER_PAYLOAD` and `BOARD_SCAN_TARGET_PAYLOAD` are named by scan behavior only; broader piece semantics remain open. |
| Landing scan state | What are `$C69D`, `$C6AE`, `$C6BF`, and `$C6C0` semantically? | Reset/write/decrement patterns are real, but only `$C6BF` has a confirmed read/write role in scan/landing timing. |
| Sprite object slots | What are slot-local bytes `+$01`, `+$03`, `+$05`, and `+$0F`? | `UpdateSpriteObject` stages slots 1-4, but those offsets still need a dedicated producer/consumer trace. |
| High-bit object types | Are there semantic high-bit sprite object types? | `UpdateSprites` does not mask bit 7 before indexing the frame table; call-site evidence is still incomplete. |
| Sound commands | What are the full command semantics and channel roles in the recovered music streams? | Sound state and index tables are structured, but medium-confidence `SOUND_CH_*` names need more sequence decoding. |
| Bank 3 graphics | Which exact screen regions do remaining Bank 3 tile ranges represent? | Load paths and VRAM destinations are documented, but several ranges still need visual/screen-role decoding. |
| User testimony | Which ambiguous behaviors match original implementation intent? | Static analysis can show behavior, but not always why the code was structured that way. Compare with user memory where available. |

## Naming Rule

Prefer narrow names that describe the proven behavior over broad names that
guess intent. For example, `BOARD_SCAN_TARGET_PAYLOAD` is acceptable because it
describes the observed scan target; a concrete piece-name label should wait
until the payload's player-visible meaning is proven.

