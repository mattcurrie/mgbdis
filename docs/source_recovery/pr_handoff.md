# Source Recovery PR Handoff

This document records the content, method, reliability evidence, token usage,
and operational lessons for the YOSSY NO TAMAGO source recovery pull request.
It is intentionally broader than a normal PR description so the review history
and process risks remain available in the repository.

## PR Scope

The final local review stack before this handoff document was:

| Commit | Purpose | Review result |
|--------|---------|---------------|
| `6c35953 Complete recovered Yossy no Tamago source` | Recover the YOSSY NO TAMAGO GB source as maintainable RGBDS assembly while preserving the ROM. | Passed after source, symbol, branch-label, and byte-identity checks. |
| `7e6e410 Refresh source recovery graphics evidence` | Rename rendered tile-sheet evidence to match recovered graphics roles, add the Bank 2 unused-tail sheet, and keep the renderer preset aligned. | Passed after one generated-README drift was fixed and folded into the commit. |
| `9ef7b38 Document completed source recovery audit` | Record the completed 541-item audit, confidence limits, and handoff notes. | Passed after the audit docs were amended to say `541 / 541` and open `0` explicitly. |

This handoff document is an additional PR-facing documentation commit. The
local stack is based on `yoshi-disassembly-step6`; upstream `origin` only has
`master`, so a GitHub PR to upstream `master` will show the whole recovery
series, not only the final three reviewed commits.

## What Changed

- Recovered the YOSSY NO TAMAGO source organization into named RGBDS assembly
  for ROM0 and ROMX banks.
- Replaced raw WRAM-style addresses in audited Bank 0 and Bank 1 code with
  named constants or deliberately unresolved low-confidence constants.
- Recovered data/code boundaries for tables, tile data, OAM templates, sound
  sequence fragments, round-complete summary data, and other formerly ambiguous
  ranges.
- Synchronized `Yoshi/yoshi.sym` with source labels and block ranges.
- Added and used `tools/verify_yoshi_build.sh` as the behavior-preserving gate.
- Added `tools/render_gb_tiles.py` and rendered tile-sheet evidence under
  `docs/source_recovery/tile_sheets/`.
- Added subsystem notes under `docs/source_recovery/` covering memory, state
  machines, graphics loads, sound, sprite/OAM state, result records, link
  state, data ranges, and remaining evidence limits.
- Kept uncertain names narrow. Low-confidence items stay documented as evidence
  limits instead of being promoted to broad semantic names.

## What Did Not Change

- The intended runtime behavior did not change. The rebuilt `Yoshi/game.gb`
  remains byte-identical to the preserved `Yoshi/yoshi.gb`.
- The recovery did not attempt a gameplay redesign or cleanup refactor.
- The work did not use Rabbit or CodeRabbit review. The review was local
  self-review only.
- Local untracked `AGENTS.md` and `CLAUDE.md` were excluded from the stack.

## Review Method

The final review was done commit by commit:

1. Check the commit summary with `git show --stat` and `git show --name-status`.
2. Inspect relevant diffs and active documentation references.
3. Run behavior-preserving and source-structure checks.
4. Classify findings by severity.
5. Fold accepted fixes into the relevant commit with `fixup` or `amend`.

Severity policy:

| Severity | Meaning | Result in this stack |
|----------|---------|----------------------|
| P0 | Must fix immediately; behavior or build broken. | None found. |
| P1 | Must fix before PR; high-risk correctness issue. | None found. |
| P2 | Should fix before PR; documentation or review-gate inconsistency. | Fixed in `9ef7b38`. |
| P3 | Optional polish; low-risk process or generated-evidence drift. | Fixed in `7e6e410`. |

## Verification Commands

The final self-review gate used these checks:

```sh
tools/verify_yoshi_build.sh
git diff --check HEAD~3..HEAD
python3 -m py_compile tools/render_gb_tiles.py
cmp -s Yoshi/yoshi.gb Yoshi/game.gb
shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb
rg -n '^(<<<<<<<|=======|>>>>>>>)' Yoshi docs tools findings.md progress.md task_plan.md
rg -no --pcre2 '\$(?:c|C)[0-9a-fA-F]{3}' Yoshi/bank_000.asm Yoshi/bank_001.asm
rg -n 'call \$|jp \$|jr \$|^jr_[0-9a-fA-F]{3}_[0-9a-fA-F]{4}:|@\+|@-' Yoshi/bank_000.asm Yoshi/bank_001.asm
```

Additional Python checks audited:

- `Yoshi/yoshi.sym` duplicate labels.
- `Yoshi/yoshi.sym` block overlap.
- Labels in `Yoshi/yoshi.sym` missing from generated `Yoshi/game.sym`.
- Rendered tile-sheet roundtrip: `tools/render_gb_tiles.py --preset
  yoshi-graphics` reproduces the tracked README and PNG files.

## Verification Results

| Check | Result |
|-------|--------|
| `tools/verify_yoshi_build.sh` | Passed. |
| `cmp -s Yoshi/yoshi.gb Yoshi/game.gb` | Exit code `0`. |
| SHA-256 for both ROMs | `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`. |
| `git diff --check HEAD~3..HEAD` | Passed. |
| Conflict-marker scan | No matches. |
| Bank 0/1 raw `$Cxxx` scan | No matches. |
| Bank 0/1 raw direct branch scan | No matches. |
| Bank 0/1 generated local label scan | No matches. |
| Bank 0/1 anonymous relative branch scan | No matches. |
| `Yoshi/yoshi.sym` duplicate/block-overlap audit | Passed. |
| `Yoshi/yoshi.sym` labels missing from `Yoshi/game.sym` | `0`. |
| Extra generated source labels in `Yoshi/game.sym` | `50`, expected source-only globals. |
| `python3 -m py_compile tools/render_gb_tiles.py` | Passed. |
| Tile-sheet render roundtrip | Passed. |
| `task_plan.md` completion state | `541 / 541`, open `0`. |

## Reliability Assessment

High confidence:

- Byte identity is the strongest gate. The rebuilt ROM matches the preserved
  ROM byte-for-byte.
- Raw Bank 0/1 WRAM references, raw direct branches, generated local labels,
  and anonymous relative branches were removed from the audited source paths.
- `yoshi.sym` no longer has duplicate labels or overlapping block ranges in
  the audit.
- Rendered tile evidence is reproducible from the tracked ROM and renderer.

Medium confidence:

- Many subsystem names are backed by local producer/consumer patterns and table
  contracts, but exact player-visible meaning can still be refined.
- Sound engine labels and constants are structured enough for maintainability,
  but the full music-command language is not exhaustively decoded.

Low confidence and deliberate limits:

- Some write-only or single-consumer bytes remain named with `UNRESOLVED_*` or
  narrow `*_UNUSED*` names.
- Piece payload identities and some Bank 3 screen-region meanings remain
  optional future refinement work.
- No emulator playthrough or external reviewer was used as part of the final
  gate. The strongest guarantee is static source evidence plus byte identity.

## Findings From Review

Resolved findings:

- P3: The renderer preset generated
  `RoundCompleteSummaryTextTileData -> queued $9140`, while the tracked README
  described the same range as glyph records. The preset note was corrected so
  the generated evidence roundtrips exactly.
- P2: `task_plan.md` did not explicitly state open checklist item count. It now
  states open `0`.
- P2: `work_plan_and_estimate.md` still showed the old checkpoint branch and
  commit in Current Status. It now points to `codex/yoshi-recovery-review-stack`
  and the reviewed source recovery commit.

No remaining P0, P1, P2, or P3 findings are open at the time this handoff was
written.

## Things That Worked Well

- The byte-for-byte rebuild gate kept the work behavior-preserving despite the
  large assembly diff.
- Commit-level self-review made it possible to separate source recovery,
  graphics evidence, and documentation audit concerns.
- Re-rendering tile sheets into a temporary directory and comparing against the
  tracked files caught generated-evidence drift.
- Keeping low-confidence names explicit prevented evidence limits from being
  hidden inside confident-looking comments.
- `rg`-based scans made the raw address and generated-label cleanup repeatable.

## Things That Went Wrong

- Too much recovery work accumulated before a PR-shaped review boundary was
  enforced. Future source-recovery work should publish smaller PRs earlier.
- Two Codex sessions were active in the same worktree for part of the process.
  That created avoidable coordination risk. One active writer per worktree is
  safer.
- A previous name, `PIECE_DISPLAY_OBJECT_BASE_Y`, was too confident. It was
  corrected to `PIECE_DISPLAY_OBJECT_INITIAL_DELAY` after later evidence showed
  the byte was a delay, not a base Y coordinate.
- Some generated/documentation details drifted after the main recovery pass:
  the tile renderer note and the final audit status wording needed fixups.
- One review shell command used `status` as a variable name under `zsh`; that is
  a readonly shell parameter. The command failed for shell reasons and was
  rerun with `rc`.
- A first PNG-validation approach depended on a helper that was not available
  in the active Python environment. The audit switched to direct PNG signature
  checks and a full renderer roundtrip.

## Token And Time Accounting

The only exact token counter available in this local run was the Codex goal
telemetry for the final commit-level self-review goal:

| Scope | Tokens | Time |
|-------|--------|------|
| Commit-level self-review goal | `174859` | `513` seconds |

This is not a reliable total for the entire source recovery effort because
earlier work spanned prior sessions and context compactions without one shared
local token counter. Treat `174859` as the measured final-review usage, not the
whole project cost.

The user reported the active model as `gpt-5.5 xhigh`. This document records
that user-reported model context, but the repository itself does not contain an
independent API billing record.

## PR Publishing Notes

- The upstream repository is `mattcurrie/mgbdis`.
- The local authenticated account had read-only permission on upstream during
  this handoff, so the PR head is expected to be pushed to a fork.
- The upstream default branch is `master`.
- Upstream did not have a `yoshi-disassembly-step6` branch at the time of this
  handoff. Because of that, a PR to upstream `master` includes the full recovery
  series from `origin/master`, while the final local self-review specifically
  focused on the last three recovery-completion commits.

## Recommended Reviewer Focus

- Confirm that `Yoshi/yoshi.gb` is an acceptable tracked baseline ROM for this
  repository.
- Review labels and comments for overconfident semantic claims, especially in
  low-confidence WRAM, sound sequence, and piece payload areas.
- Confirm that the generated tile evidence belongs in the repository.
- Confirm whether future work should split optional refinements into follow-up
  PRs instead of extending this recovery PR.

## Current Conclusion

The final reviewed recovery stack is PR-ready. The remaining work is review
judgment, not a known local correctness blocker.
