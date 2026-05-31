# Progress Log

## Session: 2026-05-31

### Final Checklist Completion Audit
- **Status:** completed
- Actions taken:
  - Closed the remaining eight checklist items in `task_plan.md`.
  - Reclassified the former "next work" items as optional future refinements:
    low-confidence score bytes, sprite slot `+$01`, and
    `$C69D/$C6AE/$C6BF/$C6C0` stay deliberately narrow because the final audit
    found no independent consumers.
  - Updated the overview, confidence/open-question notes, next-work checklist,
    and work-plan estimate to show the 541 / 541 completion state.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - `cmp -s Yoshi/yoshi.gb Yoshi/game.gb` returned exit `0`.
  - `git diff --check` passed.
  - Strict conflict-marker scan returned no matches.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    output.
  - All `Yoshi/yoshi.sym` labels are present in rebuilt `Yoshi/game.sym`
    (`yoshi_labels_missing_from_game 0`).
  - Source-recovery checklist progress is 541 / 541 items complete.

### Phase 2/3: Shared UI Scratch HRAM Rename
- **Status:** completed
- Actions taken:
  - Renamed `$FF8D` from `TEXT_FADE` to `UI_SCRATCH` because the current source
    uses it as a shared temporary byte rather than a dedicated fade timer.
  - Renamed the related piece-display helper labels to
    `CountFieldOccupancyIntoUiScratch`,
    `AddNonForcedPieceDisplayObjectsToUiScratch`,
    `ScanPieceDisplayObjectsForUiScratchLoop`,
    `AddPieceDisplayObjectToUiScratch`, and
    `AccumulatePieceDisplayUiScratchCount`.
  - Synced `Yoshi/yoshi.sym`, memory-map notes, findings, and the task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 530 / 538 items complete.

### Phase 3/5: Round Result Entry Rename
- **Status:** completed
- Actions taken:
  - Renamed `ProcessNewHighScore` to `ProcessRoundResultAndEnterRoundEnd`
    because its callers pass general round-result codes from B-type clear,
    single-player game-over, queued 2P results, and link-result handling.
  - Renamed `ProcessBTypeClearResultHighScore` to
    `ProcessBTypeClearRoundResult`.
  - Renamed internal result-flow branch labels to `Finish2PRoundResult` and
    `HandleSinglePlayerRoundResult`.
  - Synced Bank 1 call sites, `Yoshi/yoshi.sym`, findings, docs, and the task
    plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 531 / 539 items complete.

### Phase 4: Piece Display Sprite Frame Labels
- **Status:** completed
- Actions taken:
  - Renamed Bank 1 `SpriteFrameTable_GameOverPiece`,
    `SpriteTileList_GameOverPieceFrame*`, and
    `SpriteLayout_GameOverPieceTwoTileRow` to `PieceDisplay` names.
  - Synced `Yoshi/yoshi.sym`, sprite/OAM notes, findings, task plan, and
    estimate notes.
  - Left the Bank 0 `BuildGameOverPieceDisplayObjects` path unchanged because
    that producer name still describes the slot 5-8 game-over/display builder.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 532 / 540 items complete.

### Phase 3: Round Result Comment Cleanup
- **Status:** completed
- Actions taken:
  - Updated `RESULT_FLOW_ACTIVE` and `ROUND_RESULT_PENDING` comments away from
    stale high-score wording and toward round-result/result-record flow.
  - Synced memory-map, options, state-machine, task-plan, and estimate notes.
  - Left actual result-record/high-score graphics notes untouched.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 533 / 541 items complete.

### Phase 4/5: BGM Preview 1/2 Channel 3 Visual Loop Records
- **Status:** completed
- Actions taken:
  - Rewrote `MusicSequenceData_64f0`, `64fc`, `6504`, `6536`, `6552`,
    `655a`, and `656e` with generic visual-update, rest-note, and loop command
    records.
  - Rewrote `MusicSequenceData_6b2a`, `6b42`, `6b98`, `6bac`, `6bcc`,
    `6bda`, `6bef`, `6bfb`, `6c0f`, `6c1b`, `6c27`, `6c3b`, `6c47`,
    `6c5b`, `6c67`, `6c7b`, and `6c9b` with generic visual-update,
    rest-note, channel-3 length-scale, and loop command records.
  - Preserved the existing local phrase labels and fall-through layout.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted BGM preview 1 channel-3 phrase scan reports
    `bgm_preview1_ch3_phrase_labels=7`, `visual_update=72`, `rest=72`,
    `channel3_length=1`, `loop=8`, and `raw_db=0`.
  - Targeted BGM preview 2 channel-3 phrase scan reports
    `bgm_preview2_ch3_phrase_labels=17`, `visual_update=176`, `rest=182`,
    `channel3_length=5`, `loop=17`, and `raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 529 / 537 items complete.

### Phase 4/5: BGM Preview 0 Channel 3 Visual Loop Records
- **Status:** completed
- Actions taken:
  - Rewrote `MusicSequenceData_60ce`, `60da`, `60e2`, `60ee`, `6101`,
    `6116`, `6122`, `612a`, `6136`, `6144`, `6150`, and `6158` with generic
    visual-update, rest-note, channel-3 length-scale, and loop command records.
  - Preserved the existing local phrase labels and fall-through layout.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted BGM preview 0 channel-3 phrase scan reports
    `bgm_preview0_ch3_phrase_labels=12`, `visual_update=58`, `rest=59`,
    `channel3_length=2`, `loop=13`, and `raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 527 / 535 items complete.

### Phase 4/5: Link Result Wait Inline Command Records
- **Status:** completed
- Actions taken:
  - Rewrote the remaining inline channel phrases in
    `LinkResultConfirmWaitChannel2Sequence`, `MusicSequenceData_7822`, and
    `LinkResultMenuWaitChannel2Sequence` with generic octave and rest-note
    command records.
  - Left pitch/duration bytes raw because the note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link-result wait inline scan reports `confirm_ch2=1`,
    `menu_ch1=1`, `menu_ch2=1`, `length_envelope=5`, `octave=20`,
    `rest=74`, `subcall=9`, `loop=3`, and `raw_db=57`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 526 / 534 items complete.

### Phase 4/5: Link Field-Rise Sound Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `MusicSequenceData_7bdf`, the channel-4 stream installed by
    `SoundIndexEntry_LinkFieldRise`, with generic gate-flag, duty/length,
    length/envelope, octave, extended-note, pitch-slide, and sequence-end
    command records.
  - Left note bytes raw because the note naming is not independently decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link field-rise sound scan reports `gate=3`, `duty=2`,
    `length_envelope=4`, `octave=4`, `extended_note=1`, `pitch_slide=1`,
    `sequence_end=3`, and `raw_db=4`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 525 / 533 items complete.

### Phase 4/5: 2P Preplay Init Phrase Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `MusicSequenceData_7965`, `MusicSequenceData_79c3`,
    `MusicSequenceData_7a2b`, and `MusicSequenceData_7a8c` with generic
    length/envelope, octave, and loop command records.
  - Left pitch/duration bytes raw because the note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted 2P preplay-init phrase scan reports
    `preplay_init_channels=4`, `phrase_labels=4`, `tempo=2`,
    `master_volume=2`, `duty=4`, `length_envelope=8`, `freq_toggle=2`,
    `octave=72`, `rest=4`, `loop=4`, and `leading_phrase_raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 524 / 532 items complete.

### Phase 4/5: Link Result Wait Phrase Command Records
- **Status:** completed
- Actions taken:
  - Rewrote the shared link-result confirm/menu wait phrase labels
    `MusicSequenceData_7690`, `76d5`, `76f4`, `7702`, `7760`, `779b`,
    `77b6`, `77c5`, `77ca`, `7806`, `784c`, `786b`, `7879`, `78d7`,
    `7912`, `792d`, and `7941` with generic octave, rest-note,
    channel-3 nested-sound-note, loop, and sequence-end command records.
  - Left pitch/duration bytes raw because the note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link-result wait phrase scan reports
    `link_result_wait_channels=8`, `phrase_labels=17`,
    `length_envelope=15`, `octave=48`, `rest=92`, `nested=44`,
    `subsequence_call=32`, `loop=14`, `sequence_end=16`, and
    `leading_phrase_raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 523 / 531 items complete.

### Phase 4/5: Link Result Confirm/Menu Wait Branch Records
- **Status:** completed
- Actions taken:
  - Rewrote the setup records in `LinkResultConfirmWaitChannel0..3Sequence`
    and `LinkResultMenuWaitChannel0..3Sequence`.
  - Rewrote the short `$FD` sub-sequence calls and `$FE` loops in the
    associated `MusicSequenceData_7671`, `MusicSequenceData_76ab`,
    `MusicSequenceData_7783`, `MusicSequenceData_77eb`,
    `MusicSequenceData_7822`, and `MusicSequenceData_78fa` streams.
  - Left the longer note/pitch streams raw where note naming is not
    independently decoded.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link-result wait/menu scan reports
    `link_result_wait_menu_labels=8`, `tempo=2`, `duty=4`, `vibrato=4`,
    `freq_toggle=2`, `length_envelope=15`, `channel3_length=2`, `rest=28`,
    `subcall=32`, `loop=8`, and `raw_db=44`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 522 / 530 items complete.

### Phase 4/5: 2P Result Channel Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `Result2PNonzeroRankChannel0/1Sequence` and
    `Result2PZeroRankChannel0/1Sequence` with generic setup, octave, rest-note,
    pitch-slide, frequency-carry, and sequence-end command records.
  - Left pitch/duration bytes raw because the note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted 2P result scan reports `result_2p_labels=4`, `tempo=2`,
    `master_volume=2`, `freq_toggle=2`, `duty=4`, `length_envelope=6`,
    `octave=12`, `rest=11`, `pitch_slide=8`, `sequence_end=4`, and
    `leading_raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 520 / 528 items complete.

### Phase 4/5: Link Result Nonzero/Zero Channel Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `LinkResultNonzeroChannel0..2Sequence` and
    `LinkResultZeroChannel0..2Sequence` with generic setup, octave,
    rest-note, vibrato, frequency-carry, and sequence-end command records.
  - Left pitch/duration bytes raw because note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link-result nonzero/zero scan reports
    `link_result_nz_zero_labels=6`, `tempo=2`, `duty=4`, `vibrato=4`,
    `freq_toggle=2`, `length_envelope=9`, `octave=14`, `rest=5`,
    `sequence_end=6`, and `raw_db=14`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 520 / 528 items complete.

### Phase 4/5: Confirm Channel Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `ConfirmChannel0..3Sequence` with generic setup, octave,
    rest-note, pitch-slide, channel-3 length-scale, nested-sound-note, and
    sequence-end command records.
  - Left pitch/duration bytes raw because note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted confirm scan reports `confirm_labels=4`, `tempo=1`,
    `master_volume=1`, `duty=2`, `vibrato=2`, `freq_toggle=1`,
    `length_envelope=13`, `octave=9`, `rest=9`, `pitch_slide=3`,
    `channel3_length=3`, `nested=28`, `sequence_end=4`, and `raw_db=14`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 519 / 527 items complete.

### Phase 4/5: 1P Result Channel Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `Result1PNoRankChannel0..2Sequence` and
    `Result1PRankedChannel0..1Sequence` with generic setup, octave, rest-note,
    vibrato, frequency-carry, and sequence-end command records.
  - Left pitch/duration bytes raw because the note naming is not independently
    decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted 1P result scan reports `result_1p_labels=5`, `tempo=2`,
    `master_volume=2`, `freq_toggle=2`, `duty=4`, `length_envelope=8`,
    `vibrato=4`, `octave=23`, `rest=3`, `sequence_end=5`, and
    `leading_raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 519 / 527 items complete.

### Phase 4/5: Link Role Channel Command Records
- **Status:** completed
- Actions taken:
  - Rewrote `LinkRoleSharedChannel0Sequence`,
    `LinkMasterChannel1/2/3Sequence`, `LinkSlaveChannel1/2Sequence`, and the
    short link-role `$FD/$FE` call/loop records with generic sound-command
    macros.
  - Preserved the existing `MusicSequenceData_71e4` boundary inside
    `LinkSlaveChannel3Sequence` by spelling the split `$FD` pointer with
    `LOW(MusicSequenceData_71f2)` / `HIGH(MusicSequenceData_71f2)`.
  - Left the longer music phrases behind `MusicSequenceData_*` labels raw.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link-role command scan reports `tempo=1`, `master_volume=1`,
    `duty=1`, `vibrato=1`, `freq_toggle=3`, `length_envelope=6`, `octave=7`,
    `rest=9`, `subcall=17`, `loop=4`, and `split_subcall=1`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 518 / 526 items complete.

### Phase 4/5: BGM Option 2 And Preview 2 Command Records
- **Status:** completed
- Actions taken:
  - Rewrote the top-level `BgmOption2Channel0..3Sequence` and
    `BgmPreview2Channel0..3Sequence` heads with generic setup, octave,
    rest-note, visual-update, vibrato, and frequency-carry command records.
  - Left the longer music phrases behind `MusicSequenceData_*` labels raw.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted BGM option/preview 2 scan reports `option2_preview2_labels=8`,
    `tempo=2`, `master_volume=2`, `freq_toggle=2`, `duty=4`,
    `length_envelope=5`, `vibrato=4`, `octave=12`, `rest=15`,
    `channel3_length=2`, `visual_update=8`, and `leading_raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 516 / 524 items complete.

### Phase 4/5: BGM Option 1 And Preview 1 Command Records
- **Status:** completed
- Actions taken:
  - Rewrote the top-level `BgmOption1Channel0..3Sequence` and
    `BgmPreview1Channel0..3Sequence` heads with generic setup, octave,
    rest-note, visual-update, vibrato, and frequency-carry command records.
  - Left the longer music phrases behind `MusicSequenceData_*` labels raw.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted BGM option/preview 1 scan reports `option1_preview1_labels=8`,
    `tempo=2`, `master_volume=2`, `freq_toggle=2`, `duty=4`,
    `length_envelope=6`, `vibrato=2`, `octave=21`, `rest=26`,
    `channel3_length=2`, `visual_update=13`, and `leading_raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 515 / 523 items complete.

### Phase 4/5: BGM Option 0 And Preview 0 Command Records
- **Status:** completed
- Actions taken:
  - Added a generic `SOUND_VISUAL_UPDATE` record macro for the `$F1` command.
  - Rewrote the top-level `BgmOption0Channel0..3Sequence` and
    `BgmPreview0Channel0..3Sequence` heads with generic setup, octave,
    rest-note, visual-update, and frequency-carry command records.
  - Left the longer music phrases behind `SoundSequenceData_*` labels raw.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted BGM option/preview 0 scans report ch0 `tempo=2`,
    `master_volume=2`, `duty=2`, `freq_toggle=2`, `length_envelope=2`,
    `octave=5`; ch1 `duty=2`, `length_envelope=2`, `octave=2`; ch2
    `length_envelope=2`, `rest=6`, `octave=2`; and ch3 `length_scale=2`,
    `rest=8`, `visual_update=4`, `raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 514 / 522 items complete.

### Phase 4/5: 2P Preplay Init Setup Command Records
- **Status:** completed
- Actions taken:
  - Added generic `SOUND_TEMPO`, `SOUND_MASTER_VOLUME`, and
    `SOUND_FREQ_CARRY_TOGGLE` record macros for parser-confirmed command
    forms.
  - Rewrote the top-level setup bytes in
    `TwoPlayerPreplayMasterInitChannel0/1Sequence` and
    `TwoPlayerPreplaySlaveInitChannel0/1Sequence` with sound-command records.
  - Kept the following music-stream join labels address-based.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted 2P preplay setup scan reports `tempo=2`, `master_volume=2`,
    `freq_carry=5`, and `raw_db_in_preplay_setup=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 513 / 521 items complete.

### Phase 4/5: Title BGM Channel 3 Command Records
- **Status:** completed
- Actions taken:
  - Added generic record macros for the channel-3 one-byte length-scale form,
    rest notes, channel-3 nested-sound note commands, and `$FE` loop jumps.
  - Rewrote `TitleBgmChannel3Sequence` and `SoundSequenceData_5a89` with those
    records, leaving pitch names and phrase names unassigned.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted Title BGM channel-3 scan reports `title_bgm_ch3_labels=1`,
    `length_scale=1`, `rest=2`, `nested_sound_notes=47`, `loop_jump=1`, and
    `raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 512 / 520 items complete.

### Phase 4/5: Result And 2P Preplay Sound Channel Sequence Labels
- **Status:** completed
- Actions taken:
  - Renamed the direct `SoundIndexEntry_Result1PNoRank` and
    `SoundIndexEntry_Result1PRanked` channel streams to
    `Result1PNoRankChannel*Sequence` and `Result1PRankedChannel*Sequence`.
  - Renamed the direct `SoundIndexEntry_TwoPlayerPreplayMasterInit` and
    `SoundIndexEntry_TwoPlayerPreplaySlaveInit` channel streams to
    `TwoPlayerPreplayMasterInitChannel*Sequence` and
    `TwoPlayerPreplaySlaveInitChannel*Sequence`.
  - Renamed the direct `SoundIndexEntry_Result2PNonzeroRank` and
    `SoundIndexEntry_Result2PZeroRank` channel streams to
    `Result2PNonzeroRankChannel*Sequence` and
    `Result2PZeroRankChannel*Sequence`.
  - Kept internal music-stream join labels address-based.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, data-range notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted result/preplay scan reports `result_preplay_labels=13`,
    `pointers=13`, and `old_entry_labels=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 511 / 519 items complete.

### Phase 4/5: Title BGM Channel 1 Command Records
- **Status:** completed
- Actions taken:
  - Added a generic `SOUND_VIBRATO` record macro for the `$EA` command.
  - Rewrote the high-confidence setup commands in `TitleBgmChannel1Sequence`
    as `SOUND_DUTY_LENGTH`, `SOUND_VIBRATO`, `SOUND_LENGTH_ENVELOPE`, and
    `SOUND_OCTAVE` records.
  - Left note bytes raw because their pitch/duration naming is not yet
    independently decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted Title BGM channel-1 scan reports `title_bgm_ch1_labels=1`,
    `duty=1`, `vibrato=1`, `length_envelope=3`, `octave=5`, and
    `raw_db_lines=7`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 510 / 518 items complete.

### Phase 4/5: Link Role And Result Sound Channel Sequence Labels
- **Status:** completed
- Actions taken:
  - Renamed the direct `SoundIndexEntry_LinkMaster` and
    `SoundIndexEntry_LinkSlave` sequence targets. Channel 0 is shared as
    `LinkRoleSharedChannel0Sequence`; channels 1-3 are split into
    `LinkMasterChannel*Sequence` and `LinkSlaveChannel*Sequence`.
  - Renamed the direct confirm/link-result sequence targets to
    `ConfirmChannel*Sequence`, `LinkResultNonzeroChannel*Sequence`,
    `LinkResultZeroChannel*Sequence`, `LinkResultConfirmWaitChannel*Sequence`,
    and `LinkResultMenuWaitChannel*Sequence`.
  - Kept internal music-stream join labels address-based.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, data-range notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted link/result scan reports `link_role_labels=7`,
    `link_role_pointers=8`, `link_result_labels=18`,
    `link_result_pointers=18`, and `old_entry_labels=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 509 / 517 items complete.

### Phase 4/5: Title BGM Channel 2 Command Records
- **Status:** completed
- Actions taken:
  - Moved the reusable sound command record macros before the main Bank 1 music
    sequence block so top-level BGM streams can use them.
  - Added `SOUND_SUBSEQUENCE_CALL` for the `$FD` returnable sub-sequence command.
  - Rewrote `TitleBgmChannel2Sequence` as one `SOUND_LENGTH_ENVELOPE $06, $12`
    command followed by four `SOUND_SUBSEQUENCE_CALL SoundSequenceData_5a34`
    records.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted Title BGM channel-2 scan reports `title_bgm_ch2_labels=1`,
    `length_envelope=1`, `subsequence_calls=4`, and `raw_db=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 507 / 515 items complete.

### Phase 4/5: BGM Option And Preview Channel Sequence Labels
- **Status:** completed
- Actions taken:
  - Renamed the 24 direct `SoundIndexEntry_BgmOption0..2` and
    `SoundIndexEntry_BgmPreview0..2` sequence targets to
    `BgmOption*Channel*Sequence` and `BgmPreview*Channel*Sequence`.
  - Kept internal `$FD/$FE` music-stream join labels address-based, because
    their phrase/command roles remain undecoded.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, data-range notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted BGM entry scan reports `bgm_entry_labels=28`, `pointers=28`, and
    `old_entry_labels=0` across Title, option, and preview BGM entries.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 506 / 514 items complete.

### Phase 4/5: Title BGM Channel Sequence Labels
- **Status:** completed
- Actions taken:
  - Renamed the four direct `SoundIndexEntry_TitleBgm` sequence targets from
    address-based `SoundSequenceData_*` names to
    `TitleBgmChannel0Sequence` through `TitleBgmChannel3Sequence`.
  - Kept the internal `$FD/$FE` music-stream join labels address-based because
    their phrase/command roles are not yet decoded.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, data-range notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted Title BGM scan reports `title_bgm_labels=4`, `pointers=4`, and
    `old_entry_labels=0`.
  - Bank 0/1 raw WRAM, raw direct branch, generated local-label, and anonymous
    branch scans all returned no matches.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches; `Yoshi/game.sym` missing-label audit reports `missing 0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 505 / 513 items complete.

### Phase 4/5: Sound Support Table Records
- **Status:** completed
- Actions taken:
  - Added `SOUND_WAVE_DUTY_END`, `SOUND_REGISTER_OFFSET_ENTRY`,
    `SOUND_CHANNEL_MASK_ENTRY`, and `SOUND_PITCH_BASE_ENTRY` record macros.
  - Rewrote `SoundWaveDutyData`, `SoundRegisterOffsetTable`,
    `SoundChannelDisableMaskTable`, `SoundChannelEnableMaskTable`, and
    `SoundPitchBaseTable` to use those record macros.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted sound-support scan reports `wave_end=1`, `register_offsets=8`,
    `channel_masks=16`, `pitch_entries=12`, and `raw_db_dw=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 505 / 513 items complete.

### Phase 1/4: Cartridge Nintendo Logo Macro
- **Status:** completed
- Actions taken:
  - Replaced the literal 48-byte `HeaderLogo` payload with RGBDS's built-in
    `NINTENDO_LOGO` macro from `hardware.inc`.
  - Kept `HeaderTitle` and the named `HEADER_*` metadata fields unchanged.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 503 / 511 items complete.

### Phase 4/5: Tail Gate And Pitch-Slide Sound Records
- **Status:** completed
- Actions taken:
  - Added generic `SOUND_LENGTH_ENVELOPE`, `SOUND_OCTAVE`,
    `SOUND_GATE_FLAG`, and `SOUND_PITCH_SLIDE` records for decoded sound
    command forms.
  - Rewrote `SoundSequenceData_7f65` and `SoundSequenceData_7f80` from raw
    bytes to command records after confirming the `$DC`, `$E5`, `$F8`, and
    `$EB` operand lengths in the parser.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted tail sequence scan reports `tail_labels=10`, `duty=7`,
    `extended_note=22`, `channel7_note=8`, `gate=2`, `length_envelope=2`,
    `octave=2`, `pitch_slide=2`, `end=8`, and `raw_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 502 / 510 items complete.

### Phase 4/5: Pause Secondary Sound Sequence Records
- **Status:** completed
- Actions taken:
  - Rewrote `SoundSequenceData_7e15`, the channel-5 half of the count-2 pause
    sound pair, with `SOUND_DUTY_LENGTH`, repeated `SOUND_EXTENDED_NOTE`, and
    `SOUND_SEQUENCE_END`.
  - Kept the paired `SoundSequenceData_7dff` bytes raw because the same address
    is also selected by `SoundWavePatternPointerTable`.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted pause-secondary scan reports `pause_secondary_labels=1`,
    `duty=1`, `extended_note=5`, `end=1`, and `raw_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 501 / 509 items complete.

### Phase 4/5: Tail Sound Sequences And Bank 1 Padding
- **Status:** completed
- Actions taken:
  - Rewrote the tail-adjacent short sequences at `SoundSequenceData_7f0d`,
    `7fb4`, `7fd0`, and `7fe3` with `SOUND_DUTY_LENGTH`,
    `SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END`.
  - Preserved the shared end-only labels `SoundSequenceData_7f1b` and
    `SoundSequenceData_7fc2`, which are direct sound-index targets and
    fallthrough terminators for the preceding sequences.
  - Added `SOUND_CHANNEL7_EXTENDED_NOTE note, param0, param1` for channel-7
    streams and rewrote `SoundSequenceData_7f1c` and `7fc3` with that two-operand
    extended-note record shape.
  - Split the final ten bytes at `01:$7FF6-$7FFF` into
    `Bank1TailPaddingData`, emitted as five `BANK1_TAIL_PADDING_WORD`
    entries with `BANK1_TAIL_PADDING_WORDS`.
  - Split the Bank 1 tail symbol data range so the sound sequence block ends at
    `01:$7FF5` and the padding block starts at `01:$7FF6`.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted tail sequence scan reports `tail_labels=8`, `duty=4`,
    `extended_note=14`, `channel7_note=8`, `end=6`, and `raw_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 500 / 508 items complete.

### Phase 4/5: Sweep And Extended-Note Effect Sequence Records
- **Status:** completed
- Actions taken:
  - Added the generic `SOUND_SWEEP value` record for the `$10` sound parser
    command that writes the sweep register path.
  - Rewrote the remaining short channel-4 sweep/extended-note effects at
    `SoundSequenceData_7e4b`, `7e5c`, `7eda`, `7eeb`, `7ef6`, `7f29`,
    `7f34`, `7f43`, `7f52`, and `7f9d` to use `SOUND_DUTY_LENGTH`,
    `SOUND_SWEEP`, `SOUND_EXTENDED_NOTE`, and `SOUND_SEQUENCE_END`.
  - Kept extended-note operands generic pending a separate channel-specific
    hardware mapping pass.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted sweep/extended-note scan over the converted labels reports
    `short_effect_sequence_labels=13 duty=13 sweep=26 extended_note=35
    end=13 raw_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 499 / 507 items complete.

### Phase 4/5: DropStart And Board-Scan Extended Note Records
- **Status:** completed
- Actions taken:
  - Added generic `SOUND_DUTY_LENGTH`, `SOUND_EXTENDED_NOTE`, and
    `SOUND_SEQUENCE_END` record macros for decoded sound-command streams.
  - Rewrote `SoundSequenceData_7e2c`, `SoundSequenceData_7eb4`, and
    `SoundSequenceData_7ec7` from raw bytes to those command records.
  - Left the extended-note operands generic until their channel-specific
    hardware meaning is independently decoded.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted extended-note scan reports
    `sound_duty_length_records=3 sound_extended_note_records=15
    sound_sequence_end_records=3 raw_target_sequences=0`.
  - Source-recovery checklist progress is 498 / 506 items complete.

### Phase 4/5: Board-Scan Step Sound Sequence Records
- **Status:** completed
- Actions taken:
  - Added `SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE duty, sweep, note, envelope,
    freq_lo, freq_hi, final_sweep` for short channel-4 extended-note effects.
  - Rewrote `SoundSequenceData_7e67` through `SoundSequenceData_7ea9`, the
    `SoundIndexEntry_BoardScanStep0..6` targets, to use the new record macro.
  - Left the separate step-7 channel-5 target raw because it uses a longer
    sequence and needs a separate command-stream pass.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted board-scan sound scan reports
    `board_scan_sweep_note_sequences=7` and
    `raw_board_scan_sweep_note_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 497 / 505 items complete.

### Phase 4/5: Round-Complete Graphic Tile Records
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS` for the ROM0
    A-type round-complete summary/reveal graphics.
  - Rewrote the 80 copied 16-byte tiles under
    `RoundCompleteSummaryGraphicTileData` as paired 8-byte four-row records,
    avoiding RGBDS two-digit macro arguments and preserving raw `$Cxxx` scan
    cleanliness.
  - Updated graphics/data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted graphic-tile scan reports
    `graphic_tile_4row_records=160 bad_records=0 raw_graphic_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 496 / 504 items complete.

### Phase 4/5: Channel-7 Short Sound Sequence Records
- **Status:** completed
- Actions taken:
  - Added `SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE param0, param1` for the
    short channel-7 effect sequences at `01:$7D85-$7DBC`.
  - Rewrote `SoundSequenceData_7d85` through `SoundSequenceData_7db9` from raw
    four-byte rows into one extended-note command, two generic operands, and
    `SOUND_SEQUENCE_END_COMMAND`.
  - Kept the operand names generic until the channel-7 hardware write semantics
    are decoded independently.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted channel-7 scan reports `channel7_extended_note_sequences=14` and
    `raw_channel7_sequence_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 495 / 503 items complete.

### Phase 4/5: ROM0 Tail Padding Prefix Structure
- **Status:** completed
- Actions taken:
  - Added `BANK0_TAIL_PADDING_WORD` and
    `BANK0_TAIL_PADDING_PREFIX_WORDS` for the unreferenced ROM0 tail at
    `00:$3E49-$3FFF`.
  - Rewrote `Bank0TailPaddingData` as a 204-word `$0039` `REPT` prefix
    followed by the observed 31-byte suffix, preserving the exact tail bytes.
  - Updated graphics/data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted ROM0 tail scan reports
    `bank0_tail_len=439 repeated_3900_pairs=204 suffix_len=31`, and source
    structure scan reports
    `bank0_tail_rept_refs=1 bank0_tail_word_refs=1 bank0_tail_suffix_db=3`.
  - Targeted Bank 1 wave-pattern scan reports
    `sound_wave_pattern_rows=6 old_sound_wave_pattern_bytes_refs=0`, guarding
    against the earlier two-digit macro-argument truncation pitfall.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 494 / 502 items complete.

### Phase 4/5: Sound Wave Pattern Records
- **Status:** completed
- Actions taken:
  - Added `SOUND_WAVE_PATTERN_POINTER` records for the nine-entry
    `SoundWavePatternPointerTable`.
  - Added `SOUND_WAVE_PATTERN_ROW` records for the three dedicated 16-byte
    waveforms `SoundWavePatternData_0..2`.
  - Left `SoundWavePatternData_SharedSequence` as sequence `db` because the
    same address is also `SoundSequenceData_7dff`.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Error resolved:
  - First attempted a 16-argument wave-pattern macro. RGBDS interpreted
    `\10`-style arguments incorrectly, emitted truncation warnings, and the
    rebuilt ROM differed. Replaced it with paired 8-byte
    `SOUND_WAVE_PATTERN_ROW` records, after which the build returned to
    byte-identical output.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted sound-wave scan reports `sound_wave_pattern_pointers=9`,
    `raw_sound_wave_pattern_dw=0`, `sound_wave_pattern_rows=6`, and
    `raw_dedicated_wave_pattern_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 493 / 501 items complete.

### Phase 4/5: Settings Cursor Init Records
- **Status:** completed
- Actions taken:
  - Added `SETTINGS_CURSOR_INIT_RECORD frame, base_x` for the three
    settings-cursor sprite object initializer records.
  - Rewrote `SettingsCursorSpriteInit0..2` to use the record macro while
    preserving the exact 7-byte copy records consumed by `ApplySettings`.
  - Updated sprite/OAM notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted settings-cursor init scan reports
    `settings_cursor_init_records=3` and `raw_settings_cursor_init_rows=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 491 / 499 items complete.

### Phase 4/5: Game-Over Zero Result And No-Rank Comments
- **Status:** completed
- Actions taken:
  - Added `RESULT_RANK_NONE` for the zero rank/high-score position.
  - Added source comments at the byte-preserving `xor a` sites that enter the
    2P zero-result game-over path, the 1P no-rank game-over path, and the
    master-side tied-result resolver.
  - Updated result-record, memory-map, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted zero-result/no-rank scan reports `result_rank_none_refs=7` and
    `semantic_zero_comments=13`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 490 / 498 items complete.

### Phase 4/5: Option And Palette Entry Macros
- **Status:** completed
- Actions taken:
  - Added `PREPLAY_OPTION_COUNT_ENTRY` for the detached and live 1P pre-play
    option-count tables.
  - Added `LINK_SETTINGS_OPTION_COUNT_ENTRY` for the 2P link settings
    option-count table.
  - Added `RESULT_RECORD_PALETTE_FADE_STEP` for the four result-record palette
    fade sequence entries.
  - Updated option/link/result-record/data-range notes, findings, task-plan,
    and estimate notes.
  - Rewrote the Cxxx-shaped `RoundCompleteSummaryTextTileData` glyph bitmap
    rows as binary literals so the raw-WRAM scan no longer mistakes font rows
    for WRAM addresses.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted option/count/palette scan reports
    `preplay_option_count_entries=8`, `raw_preplay_option_count_db=0`,
    `link_settings_option_count_entries=2`,
    `raw_link_settings_option_count_db=0`, `result_palette_steps=4`,
    `raw_result_palette_db=0`, and `cxxx_like_bank0_matches=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 489 / 497 items complete.

### Phase 4/5: Round-Complete Text Glyph Tile Records
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE` records for the 17 ROM0
    round-complete summary glyph tiles.
  - Rewrote `RoundCompleteSummaryTextTileData` so each tile is keyed by the same
    `ROUND_COMPLETE_SUMMARY_TEXT_TILE_*` constants used by the decoded
    `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER` message records.
  - Updated graphics-load, tile-sheet, data-range, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted glyph scan reports `round_complete_text_glyph_tiles=17` and
    `raw_round_complete_text_db=0`.
  - Targeted cartridge-header scan still reports `header_metadata_constants=12`
    and `raw_header_metadata_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 488 / 496 items complete.

### Phase 1/4: Cartridge Header Metadata Constants
- **Status:** completed
- Actions taken:
  - Added `HEADER_*` constants for the cartridge header metadata bytes from the
    new-licensee code through the global checksum.
  - Rewrote `HeaderNewLicenseeCode` through `HeaderGlobalChecksum` to use the
    named constants while leaving the fixed Nintendo logo and title bytes as
    then-literal source bytes.
  - Updated baseline, data-range, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted cartridge-header scan reports `header_metadata_constants=12` and
    `raw_header_metadata_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 486 / 494 items complete.

### Phase 4/5: Level Lookup Entry Macros
- **Status:** completed
- Actions taken:
  - Added `B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY` for the five B-type initial board
    top-row seed entries.
  - Added `GAME_TURN_LEVEL_START_INDEX_ENTRY` for the five A-type game-turn
    start-index entries.
  - Added `LEVEL_FALL_DELAY_ENTRY` for the 20 capped level fall-delay entries.
  - Updated data-range notes, fall-timing notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted level lookup scan reports `btype_seed_entries=5`,
    `raw_btype_seed_db=0`, `game_turn_start_entries=5`,
    `raw_game_turn_start_db=0`, `level_fall_delay_entries=20`, and
    `raw_level_fall_delay_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 485 / 493 items complete.

### Phase 4: One-Player Preplay Game-Type Text Row Macro
- **Status:** completed
- Actions taken:
  - Added local `PREPLAY_GAME_TYPE_TEXT_ROW_START` and
    `PREPLAY_GAME_TYPE_TEXT_ROW_END` records for the 12-tile game-type text rows.
  - Rewrote `RestartTextBlock0..2` as paired six-tile start/end fragments.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted game-type scan reports `game_type_starts=6`,
    `game_type_ends=6`, and `raw_game_type_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 484 / 492 items complete.

### Phase 4: Duplicate OFF Text Row Macro
- **Status:** completed
- Actions taken:
  - Rewrote `ContinueOffText` with the existing `OPTION_TEXT_ROW_3` macro.
  - Reused `OPTION_TEXT_TILE_O` and `OPTION_TEXT_TILE_F` so the duplicate BGM
    `OFF` text now matches the option text alphabet representation.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted duplicate-off scan reports `continue_off_rows=1` and
    `raw_continue_off_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 483 / 491 items complete.

### Phase 4: One-Player Preplay Header Text Row Macro
- **Status:** completed
- Actions taken:
  - Added `OPTION_TEXT_TILE_R`, `OPTION_TEXT_TILE_Y`, and
    `PREPLAY_HEADER_TEXT_TILE_1`.
  - Added local `PREPLAY_HEADER_TEXT_ROW_START_8`,
    `PREPLAY_HEADER_TEXT_ROW_END_5`, and `PREPLAY_HEADER_TEXT_ROW_END_4`
    records for the two long `DrawStringToGrid` rows.
  - Rewrote `ResultHeaderText` as the decoded `1 PLAYER GAME` and
    `YOSSY EGGS` header rows.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted preplay header scan reports `header_starts=2`,
    `header_ends=2`, and `raw_header_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 482 / 490 items complete.

### Phase 4/5: One-Byte Lookup Table Entry Macros
- **Status:** completed
- Actions taken:
  - Added `MATCHING_TILE_BASE_INDEX_ENTRY` for the 28-byte matching tile-base
    lookup table indexed by `STATE_TRANSITION`.
  - Added `BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY` for the seven-byte
    board-scan transition frame-limit table indexed by the pre-remap
    `SCREEN_STATE`.
  - Rewrote both tables with one entry per consumed byte.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted lookup-table scan reports `matching_tile_base_entries=28`,
    `raw_matching_tile_base_db=0`, `board_scan_frame_limit_entries=7`, and
    `raw_board_scan_frame_limit_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 482 / 490 items complete.

### Phase 4: Option Text Row Macro
- **Status:** completed
- Actions taken:
  - Added `OPTION_TEXT_TILE_*` constants for the option label tile alphabet used
    by `OptionTextAGame` through `OptionTextOff`.
  - Added local `OPTION_TEXT_ROW_3`, `OPTION_TEXT_ROW_4`,
    `OPTION_TEXT_ROW_5`, and `OPTION_TEXT_ROW_6` records.
  - Rewrote the eight option label strings as row records for `A GAME`,
    `B GAME`, `LEVEL`, `SPEED`, `BGM`, `LOW`, `HIGH`, and `OFF`.
  - Updated option UI data-range notes, option variable notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted option text scan reports `option_text_rows=8` and
    `raw_option_text_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 480 / 488 items complete.

### Phase 4: Countdown Digit Pattern Record Macro
- **Status:** completed
- Actions taken:
  - Added local `COUNTDOWN_DIGIT_PATTERN` records for the 8-byte digit bitmap
    entries used by `UpdateCountdownTimer`.
  - Rewrote `CountdownDigitPattern0..9` with the record macro.
  - Updated countdown/data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted countdown pattern scan reports `countdown_digit_patterns=10` and
    `raw_countdown_pattern_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 480 / 488 items complete.

### Phase 4: BGM Marker Text Row Macro
- **Status:** completed
- Actions taken:
  - Added `PREPLAY_BGM_MARKER_TEXT_WIDTH` and selected-marker offset constants
    for BGM options 0, 1, 2, and off.
  - Added local `PREPLAY_BGM_MARKER_TEXT` and
    `PREPLAY_BGM_MARKER_NONE_TEXT` records.
  - Rewrote `BgmMarker0Text..BgmMarkerNoneText` with the row macros.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted BGM marker scan reports `bgm_marker_rows=4`,
    `bgm_marker_none_rows=1`, and `raw_bgm_marker_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 478 / 486 items complete.

### Phase 4/5: Option Marker And Cursor Triplet Records
- **Status:** completed
- Actions taken:
  - Added `OPTION_MARKER_POSITION` for the two-byte row/column coordinate
    records consumed by `DrawOptionMarkers`.
  - Added `DRAW_TILE_TRIPLET` for row/column/tile tuples consumed by
    `DrawTileTripletList`.
  - Rewrote all eight option marker positions, six inactive cursor triplets,
    and six highlighted cursor triplets with those macros.
  - Updated option UI data-range notes, option variable notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted option UI scan reports `option_marker_records=8`,
    `raw_marker_db=0`, `option_triplet_records=12`, and `raw_triplet_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 477 / 485 items complete.

### Phase 4: Two-Player Role Header Text Macro
- **Status:** completed
- Actions taken:
  - Added `TWO_PLAYER_ROLE_HEADER_SUFFIX_TILE_0` and
    `TWO_PLAYER_ROLE_HEADER_SUFFIX_TILE_1`.
  - Added local `TWO_PLAYER_ROLE_HEADER_TEXT` records for
    `ScoreHeaderTextRole1` and `ScoreHeaderTextRoleOther`.
  - Reused the existing `TWO_PLAYER_ROLE_HEADER_TILE_ROW_0/1` constants to
    express the two swapped role header tile runs.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted role-header scan reports `role_header_rows=2` and
    `raw_role_header_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 476 / 484 items complete.

### Phase 4/5: Grid And Column Pattern Row Macros
- **Status:** completed
- Actions taken:
  - Added `GRID_PIECE_PATTERN_ROW` for the direct four-tile rows consumed by
    `DrawGridPiece`.
  - Added `COLUMN_SPRITE_PATTERN_ROW` for the four-tile rows consumed by
    `DrawColumnSprite` and for the separated unreached column-sprite tail.
  - Rewrote all 18 grid-piece rows and all 28 column-sprite/tail rows with the
    new row macros.
  - Updated board-layout notes, data-range notes, findings, task-plan, and
    estimate notes.
  - Re-read the affected docs after an initial context-mismatch patch failure,
    then applied the updates against the current file contents.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted pattern-row scan reports `grid_pattern_rows=18`,
    `raw_grid_pattern_db=0`, `column_pattern_rows=28`, and
    `raw_column_pattern_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 475 / 483 items complete.

### Phase 4: Preplay Speed Text Row Macro
- **Status:** completed
- Actions taken:
  - Added local `PREPLAY_SPEED_TEXT_ROW` records for the two-line
    `ResultTextBlock0..2` data used by 1P and 2P preplay speed rendering.
  - Replaced the raw speed text `db` rows with the row macro while preserving
    the non-consecutive `$9D` tile in `ResultTextBlock0`.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted speed text scan reports `preplay_speed_rows=6` and
    `raw_speed_text_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 474 / 482 items complete.

### Phase 4: Piece Preview Text Cell Macro
- **Status:** completed
- Actions taken:
  - Added `PIECE_PREVIEW_LEVEL0_TILE` through `PIECE_PREVIEW_LEVEL4_TILE`.
  - Added selected/unselected preview-cell tile constants for the top, middle,
    and bottom rows of the level preview cells.
  - Added local `PIECE_PREVIEW_*_CELL` macros and rewrote
    `PiecePreviewText0..4` plus `PiecePreviewBlankText` with those cell records.
  - Updated Bank 0 text data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted piece-preview scan reports `piece_preview_top_cells=30`,
    `middle_cells=30`, `bottom_cells=30`, and `raw_literal_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 473 / 481 items complete.

### Phase 4/5: Round-Complete Summary Message Half Macro
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_SUMMARY_MESSAGE_HALF` for the six-byte halves of the
    three A-type round-complete summary messages.
  - Rewrote `RoundCompleteSummaryMessageVeryGood`,
    `RoundCompleteSummaryMessageExcellent`, and
    `RoundCompleteSummaryMessageSuperPlayer` as two half-records each.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted summary-message scan reports `summary_message_halves=6` and
    `raw_summary_message_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 472 / 480 items complete.

### Phase 4: Title Label Text Row Macro
- **Status:** completed
- Actions taken:
  - Added title-label text constants for the player/Yoshi prefix tiles, the
    separator tile, and the shared six-tile suffix base.
  - Added local `TITLE_LABEL_TEXT_ROW` records for the two
    `DrawStringToGrid` rows consumed by `DrawTitleLabels`.
  - Rewrote `TitleLabelTextPlayer` and `TitleLabelTextYoshi` with the row
    macro instead of raw `db` tile streams.
  - Updated title-menu, data-range, findings, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted title-label scan reports `title_label_rows=2` and
    `raw_title_label_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 471 / 479 items complete.

### Phase 4/5: Round-Complete Final Tile Entry Macro
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_FINAL_TILE` for the one-byte final tile records
    selected by `ShowRoundComplete` through `ANIM_FRAME`.
  - Rewrote all seven `RoundCompleteFinalTileTable` entries with
    `ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_*` records.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted final-tile scan reports `final_tile_records=7` and
    `raw_final_tile_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 471 / 479 items complete.

### Phase 4/5: Round-Complete Reveal Threshold Record Macro
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_REVEAL_THRESHOLDS` for the four-byte A-type
    round-complete reveal threshold records.
  - Rewrote all seven `RoundCompleteRevealThresholdTable` records with
    500/200/100/50-point threshold arguments in consumer order.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted reveal-threshold scan reports `reveal_threshold_records=7` and
    `raw_reveal_threshold_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 469 / 477 items complete.

### Phase 4: Egg Text Tile Row Macro
- **Status:** completed
- Actions taken:
  - Added `EGG_TEXT_FRAME1_TILE_BASE`, `EGG_TEXT_FRAME2_ALT_TILE_BASE`,
    `EGG_TEXT_FRAME2_ALT_LAST_TILE`, and `EGG_TEXT_ROW_FILL_TILE`.
  - Added local `EGG_TEXT_TILE_ROW_2`, `EGG_TEXT_TILE_ROW_3`, and
    `EGG_TEXT_TILE_ROW_4` macros for the `DrawStringToGrid` rows consumed by
    `DrawEggTextFrameByIndex`.
  - Rewrote all 12 rows in `EggTextFrame0TileRows`,
    `EggTextFrame1TileRows`, and `EggTextFrame2TileRows` with those macros.
  - Updated egg-counter notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - Targeted egg-text row scan reports `egg_text_rows=12` and
    `raw_egg_text_db=0`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 468 / 476 items complete.

### Phase 4/5: Packed BCD Score Delta Entry Macro
- **Status:** completed
- Actions taken:
  - Added a local `SCORE_DELTA_ENTRY` macro for big-endian packed-BCD score
    deltas loaded into `HL` before `AddScore`.
  - Rewrote all 28 `MatchingScoreBonusTable` rows with
    `SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_*` records.
  - Rewrote all 9 `BoardScanRewardScoreDeltaTable` rows with
    `SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_*` records.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted score-delta scan reports `score_delta_entries=37` and
    `raw_score_delta_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 467 / 475 items complete.

### Phase 4: Field Column Tile Pattern Row Macro
- **Status:** completed
- Actions taken:
  - Added field-column pattern tile-role constants for blank, left-marker, and
    right-marker entries.
  - Added a local `FIELD_COLUMN_TILE_PATTERN_ROW` macro for the eight-tile rows
    inside `FieldColumnTilePatternTable`.
  - Rewrote the six raw `$4A/$FB/$FC` rows in `FieldColumnTilePatternTable`
    with role-based macro rows.
  - Updated column-state notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - Targeted field-column pattern scan reports `field_column_pattern_rows=6`
    and `raw_pattern_db=0`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 466 / 474 items complete.

### Phase 4: Bank 0 OAM Template Entry Macro
- **Status:** completed
- Actions taken:
  - Added a local `OAM_TEMPLATE_ENTRY y, x, tile, attr` macro for four-byte
    hardware OAM template rows in Bank 0.
  - Rewrote `PauseOverlayOamTemplate` as eight `OAM_TEMPLATE_ENTRY` records.
  - Rewrote `MatchingOamTemplateTop`, `MatchingOamTemplateMiddle`, and
    `MatchingOamTemplateFinal` as eight total `OAM_TEMPLATE_ENTRY` records.
  - Updated OAM/data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted OAM template scan reports `oam_template_entries=16` and
    `raw_oam_template_db=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 465 / 473 items complete.

### Phase 4: Sprite Object Pointer And Tile List Macros
- **Status:** completed
- Actions taken:
  - Added `SPRITE_OBJECT_FRAME_TABLE object_type, frame_table` for the Bank 1
    object-type pointer table consumed by `UpdateSprites`.
  - Added count-specific `SPRITE_TILE_LIST_N` macros for the sprite tile-id
    byte streams.
  - Rewrote the seven `SpriteUpdatePointerTable` entries and the 36 explicit
    `SpriteTileList_*` byte streams with those macros.
  - Left the intentional `SpriteTileList_PieceDisplayFrame22` /
    `SpriteLayout_TwoTileRow` address sharing intact.
  - Updated sprite/OAM notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted sprite scans report `sprite_object_frame_table_entries=7`,
    `raw_update_dw=0`, `sprite_tile_lists=36`, and `raw_tilelist_db=0`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 464 / 472 items complete.

### Phase 4: Sprite Layout Entry Macro
- **Status:** completed
- Actions taken:
  - Added `SPRITE_LAYOUT_ATTR_END` and `SPRITE_LAYOUT_ATTR_INHERIT`
    constants for the Bank 1 sprite layout attribute bits consumed by
    `UpdateSprites`.
  - Added a local `SPRITE_LAYOUT_ENTRY` macro for layout stream triples.
  - Rewrote the Bank 1 `SpriteLayout_*` streams as 50
    `SPRITE_LAYOUT_ENTRY y_delta, x_delta, attr` records while leaving
    `SpriteTileList_*` byte streams unchanged.
  - Updated sprite/OAM notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted sprite scans report `sprite_frame_records=80 raw_frame_dw=0` and
    `sprite_layout_entries=50 raw_layout_db=0 bad_tilelist_macros=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 463 / 471 items complete.

### Phase 4/5: Field Animation Delta Pair Macro
- **Status:** completed
- Actions taken:
  - Added a local `FIELD_ANIM_DELTA_PAIR` macro for the X/Y delta bytes
    consumed by the field animation slot update routines.
  - Rewrote `FieldSideDeltaTable` as 33 delta pairs plus
    `FIELD_ANIM_END_SENTINEL`.
  - Rewrote `FieldRowDeltaTable` as 30 delta pairs plus
    `FIELD_ANIM_END_SENTINEL`.
  - Updated field-animation notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted field-animation scan reports `side_pairs=33`, `row_pairs=30`,
    and zero raw delta `db` rows in both tables.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 462 / 470 items complete.

### Phase 4: Sprite Frame Record Macro
- **Status:** completed
- Actions taken:
  - Added a local `SPRITE_FRAME_RECORD` macro for the Bank 1 sprite animation
    frame-table format.
  - Rewrote 80 `SpriteFrameTable_*` entries from raw `dw tile_list, layout`
    lines to `SPRITE_FRAME_RECORD tile_list, layout` records.
  - Left `SpriteUpdatePointerTable`, tile lists, layouts, and all existing
    labels unchanged.
  - Updated sprite/data-range, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted sprite frame table scan reports `sprite_frame_records=80` and
    `raw_frame_dw=0`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 461 / 469 items complete.

### Phase 4: SoundIndexTable Entry Macro
- **Status:** completed
- Actions taken:
  - Added a local `SOUND_INDEX_ENTRY` macro for the Bank 1 sound index
    flags/pointer record format.
  - Rewrote `SoundIndexTable` entries from paired `db`/`dw` lines to
    `SOUND_INDEX_ENTRY flags, sequence_pointer` records, preserving existing
    alias labels and numeric continuation labels.
  - Updated data-range, sound-engine, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 460 / 468 items complete.

### Phase 3/5: Game-Turn Parameter Table Split Record Macro
- **Status:** completed
- Actions taken:
  - Added local `GAME_TURN_PARAM_SPLIT_HEAD` and
    `GAME_TURN_PARAM_SPLIT_TAIL` macros for the one record that crosses
    `GameTurnParamTableContinuation`.
  - Replaced the remaining raw three-byte record head and explicit tail byte
    with those split-record macros, keeping `00:$0C40` unchanged.
  - Updated data-range, fall-timing, piece-display, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted table scan found no raw `db $..` rows or direct
    `db GAME_TURN_PARAM_UNREAD_TAIL_VALUE`; it reports 209 complete
    `GAME_TURN_PARAM` invocations plus one split head/tail pair.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 459 / 467 items complete.

### Phase 3/5: Game-Turn Parameter Table Continuation Macro
- **Status:** completed
- Actions taken:
  - Rewrote the raw `GameTurnParamTableContinuation` byte rows as
    `GAME_TURN_PARAM` records.
  - Kept the `00:$0C40` exact-address label stable by leaving the one-byte
    tail of the crossing record as `db GAME_TURN_PARAM_UNREAD_TAIL_VALUE`.
  - Updated data-range, fall-timing, piece-display, findings, task-plan, and
    estimate notes to describe the full table body as macro-structured.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted scan of the table leaves only the intentionally split
    three-byte record head before `GameTurnParamTableContinuation`; the table
    has 209 complete `GAME_TURN_PARAM` invocations plus the split record tail.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 458 / 466 items complete.

### Phase 1/4: Interrupt Vector Padding Word Structure
- **Status:** completed
- Actions taken:
  - Added `UNUSED_INTERRUPT_VECTOR_PADDING_*` constants for the repeated
    little-endian padding word, the single zero word, and the prefix/suffix
    repeat counts.
  - Rewrote `UnusedInterruptVectorPadding` from raw byte rows to `REPT`
    blocks plus one explicit zero word, preserving the 152-byte
    `00:$0068-$00FF` range before `EntryPoint`.
  - Updated data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 457 / 465 items complete.

### Phase 3/5: Game-Turn Parameter Table Head Macro
- **Status:** completed
- Actions taken:
  - Added a local `GAME_TURN_PARAM` macro that emits the three confirmed
    consumed record bytes plus `GAME_TURN_PARAM_UNREAD_TAIL_VALUE`.
  - Rewrote the head records of `GameTurnParamTable` to use the macro instead
    of raw four-byte `db` rows.
  - Preserved the `GameTurnParamTableContinuation` exact-address landmark at
    `00:$0C40` by splitting the one record that crosses that label: the three
    consumed bytes remain before the label and the unread tail byte follows it.
  - Updated data-range, fall-timing, piece-display, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - `Yoshi/game.sym` still reports `GameTurnParamTable` at `00:0b8d` and
    `GameTurnParamTableContinuation` at `00:0c40`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 457 / 465 items complete.

### Phase 4/5: Unreached Column Sprite Tail Tile Constants
- **Status:** completed
- Actions taken:
  - Added `UNREACHED_COLUMN_SPRITE_TAIL_*_TILE` constants for the four raw
    rows in `UnreachedColumnSpritePatternTailRows`.
  - Rewrote the 16-byte tail as four four-byte rows using the scoped tail
    constants.
  - Kept these constants separate from the live
    `COLUMN_SPRITE_PATTERN_*_ENCODED_TILE` constants because no confirmed path
    indexes this tail.
  - Updated board-layout notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted scan over `UnreachedColumnSpritePatternTailRows` found no raw
    tile bytes remaining.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 455 / 463 items complete.

### Phase 4/5: Column Sprite Pattern Encoded Tile Constants
- **Status:** completed
- Actions taken:
  - Added `COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE` for the encoded blank
    source byte consumed by `CopyEncodedTilePatternRow4SkipFF`.
  - Added `COLUMN_SPRITE_PATTERN_FRAME*_COLUMN*_ROW*_TILE*_ENCODED`
    constants for the live two-frame column-sprite pattern records.
  - Rewrote the live `ColumnSpritePatternTable` frame blocks as three
    four-byte rows per 12-byte column record, matching the row-copy helper.
  - Left `UnreachedColumnSpritePatternTailRows` raw because it is outside the
    confirmed four-column/two-frame live path.
  - Updated board-layout notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - The targeted live `ColumnSpritePatternTable` scan now leaves raw tile bytes
    only in `UnreachedColumnSpritePatternTailRows`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 454 / 462 items complete.

### Phase 4/5: Unreached Falling-Piece Cleanup Byte
- **Status:** completed
- Actions taken:
  - Labeled the one-byte `pop hl` after `ClearLandedGameplayObject` as
    `UnreachedClearLandedGameplayObjectPop` in source and `Yoshi/yoshi.sym`.
  - Kept `ClearLandedGameplayObject` as the live trampoline into
    `ClearCurrentGameplaySpriteObjectRecord`; current control flow either jumps
    over the `pop hl` or returns before it.
  - Updated board-layout notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 453 / 461 items complete.

### Phase 4/5: Grid Piece Pattern Tile Constants
- **Status:** completed
- Actions taken:
  - Added `GRID_PIECE_PATTERN_*_TILE` constants for the direct 4x2 tile
    records consumed by `DrawGridPiece`.
  - Rewrote `GridPiecePatternTable` as two four-tile `db` rows per payload
    record, matching the two `CopyTilePatternRow4` calls.
  - Kept the constants scoped to record position and payload role: normal
    piece records share four frame-corner tiles, while scan trigger/target
    records use blank outer columns and their own inner tile pairs.
  - Updated board-layout notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 452 / 460 items complete.

### Phase 4/5: Sound Index Entry 0 Sentinel Fields
- **Status:** completed
- Actions taken:
  - Added `SOUND_INDEX_ENTRY_SENTINEL_FLAGS` and
    `SOUND_INDEX_ENTRY_SENTINEL_POINTER`.
  - Rewrote `SoundIndexEntry_00` to use those constants instead of raw
    `$ff/$ffff`.
  - Kept the documentation scoped to sentinel data because no live command path
    is confirmed to use sound index `$00` as a playable sound ID.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 452 / 460 items complete.

### Phase 2/4: Sound Wave Pattern Table Labels
- **Status:** completed
- Actions taken:
  - Renamed `WavePatternPointerTable` to `SoundWavePatternPointerTable` at
    `01:$7DBD`.
  - Renamed the three dedicated wave-pattern blobs to
    `SoundWavePatternData_0..2`.
  - Added the factual `SoundWavePatternData_SharedSequence` alias for the
    `$7DFF` address that is also `SoundSequenceData_7dff`, because the wave
    pointer table and sound index table both target that same byte.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, data-range notes, findings,
    and task-plan entries.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 450 / 458 items complete.

### Phase 2/5: Sound Pitch Base Table Entries
- **Status:** completed
- Actions taken:
  - Added `SOUND_PITCH_BASE_INDEX_0..11` for the 12-word
    `SoundPitchBaseTable`.
  - Rewrote `SoundPitchBaseTable` to use those constants instead of raw
    frequency base words.
  - Kept the names scoped to the `SoundUpdate5` low-nibble index because the
    current code proves table indexing and octave shifting, but not note-letter
    names.
  - Updated sound-engine notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 449 / 457 items complete.

### Phase 4/5: Matching Tile-Base Index Entries
- **Status:** completed
- Actions taken:
  - Added `MATCHING_TILE_BASE_INDEX_STATE_0..27` for the 28-byte
    `MatchingTileBaseIndexTable`.
  - Rewrote the table entries to use those constants instead of raw tile-base
    index bytes.
  - Kept the constants scoped to `STATE_TRANSITION` indexes because the same
    table byte is scaled differently for the middle four-OAM group and the
    final two-OAM pair.
  - Updated matching data-range notes, sprite/OAM notes, findings, task-plan,
    and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 448 / 456 items complete.

### Phase 2/5: Sound Channel NR51 Output Mask Tables
- **Status:** completed
- Actions taken:
  - Added `SOUND_OUTPUT_CH1..4_TERMINAL_BITS` from the hardware `AUDTERM_*`
    left/right bits.
  - Added `SOUND_OUTPUT_CH1..4_CLEAR_MASK` and rewrote
    `SoundChannelDisableMaskTable` / `SoundChannelEnableMaskTable` with those
    masks.
  - Aliased `SOUND_WAVE_OUTPUT_TERMINAL_BITS` and
    `SOUND_WAVE_OUTPUT_TERMINAL_CLEAR_MASK` to the channel-3 output masks.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 448 / 456 items complete.

### Phase 4/5: Sound Index Entry Flag Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_INDEX_ENTRY_COUNT_1..4` for the high-bit field in each
    `SoundIndexTable` flags byte.
  - Added `SOUND_INDEX_ENTRY_CHANNEL_0..7` for the low-nibble channel slot.
  - Rewrote the live `SoundIndexEntry_*` flags bytes to use the count/channel
    constants instead of raw `$c0`, `$80`, `$40`, `$44`, and channel literals.
  - Deferred `SoundIndexEntry_00` sentinel naming because no live sound command
    path was confirmed to use it.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted `SoundIndexTable` scan found only the deferred
    `SoundIndexEntry_00` sentinel flags byte remaining.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 446 / 454 items complete.

### Phase 4/5: Pause Overlay OAM Template Coordinates And Tiles
- **Status:** completed
- Actions taken:
  - Added `OAM_ATTR_DMG_PALETTE_1` and `PAUSE_OVERLAY_OAM_*` constants for the
    eight-entry pause overlay hardware OAM template.
  - Rewrote `PauseOverlayOamTemplate` with named Y/X coordinate, tile, and
    attribute fields.
  - Updated data-range notes, sprite/OAM notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 446 / 454 items complete.

### Phase 4/5: Level Fall-Delay Table Entries
- **Status:** completed
- Actions taken:
  - Added `LEVEL_FALL_DELAY_INDEX_0..19` for the `LevelFallDelayTable`
    entries indexed by capped `PROGRESSION_LEVEL`.
  - Rewrote `LevelFallDelayTable` to use those constants instead of raw
    timing bytes.
  - Updated fall-timing notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 444 / 452 items complete.

### Phase 4/5: Matching OAM Template Coordinates And Initial Tiles
- **Status:** completed
- Actions taken:
  - Added `OAM_ATTR_NONE` for standard zero-attribute hardware OAM entries.
  - Added `MATCHING_TOP_OAM_*`, `MATCHING_MIDDLE_OAM_*`, and
    `MATCHING_FINAL_OAM_*` constants for the three Bank 0 matching/result OAM
    templates.
  - Rewrote `MatchingOamTemplateTop`, `MatchingOamTemplateMiddle`, and
    `MatchingOamTemplateFinal` with named Y/X coordinate, initial-tile, and
    attribute fields.
  - Updated matching data-range notes, sprite/OAM notes, findings, task-plan,
    and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 443 / 451 items complete.

### Phase 4/5: Bank 0 Tail Padding Data
- **Status:** completed
- Actions taken:
  - Renamed `Bank0TailGraphicsData` to `Bank0TailPaddingData`.
  - Confirmed the `00:$3E49-$3FFF` tail has no current source reference and is
    dominated by `$39,$00` filler pairs with a short terminal byte run.
  - Updated data-range, graphics-load, memory-map, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 442 / 450 items complete.

### Phase 4/5: Round-Complete Final Tile And Reveal Threshold Entries
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_FINAL_TILE_INDEX_0..6` for the final
    `RoundCompleteFinalTileTable` values.
  - Added `ROUND_COMPLETE_REVEAL_INDEX_*_{500,200,100,50}_THRESHOLD`
    constants for the seven `RoundCompleteRevealThresholdTable` records.
  - Updated round-complete data-range notes, sprite/OAM notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 442 / 450 items complete.

### Phase 4/5: Field Animation Dispatcher Rename
- **Status:** completed
- Actions taken:
  - Renamed the stale `SetupMultiplayer` label to
    `UpdateFieldAnimationSlots`.
  - Updated the four call sites in `Send2PData`, `ShowRoundComplete`,
    `WaitRoundCompleteRevealFramesLoop`, and `AnimateManualOamPairUpLoop`.
  - Synced `Yoshi/yoshi.sym`, `field_animation_state.md`, `link_state.md`,
    findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 440 / 448 items complete.

### Phase 4/5: Field Animation Delta Value Constants
- **Status:** completed
- Actions taken:
  - Added `FIELD_ANIM_DELTA_ZERO`, `FIELD_ANIM_DELTA_POSITIVE`, and
    `FIELD_ANIM_DELTA_NEGATIVE` beside `FIELD_ANIM_END_SENTINEL`.
  - Rewrote `FieldSideDeltaTable` and `FieldRowDeltaTable` entries with those
    aliases so the coordinate-delta meaning is explicit.
  - Rechecked the remaining open-question symbols; current source still shows
    no independent consumers for the score unused bytes, sprite slot `+$01`,
    or the `$C69D/$C6AE/$C6BF/$C6C0` landing/reset group.
  - Updated field-animation notes, data-range notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after correcting one missing
    four-byte run in the side-delta table, and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 439 / 447 items complete.

### Phase 4/5: Round Complete Summary Text Tile Data
- **Status:** completed
- Actions taken:
  - Renamed the ROM0 queued round-complete tile blocks to
    `RoundCompleteSummaryGraphicTileData` and
    `RoundCompleteSummaryTextTileData`.
  - Renamed the three A-type summary strings to
    `RoundCompleteSummaryMessageVeryGood`,
    `RoundCompleteSummaryMessageExcellent`, and
    `RoundCompleteSummaryMessageSuperPlayer`.
  - Added `ROUND_COMPLETE_SUMMARY_TEXT_TILE_*` constants so the three strings
    assemble as `VERY GOOD!`, `EXCELLENT!`, and `SUPER PLAYER` rather than raw
    tile IDs.
  - Updated source-recovery notes, rendered tile-sheet names, findings, symbol
    labels, and the render preset.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 439 / 447 items complete.

### Phase 5/5: B-Type Column Seeds And Game-Turn Level Start Indices
- **Status:** completed
- Actions taken:
  - Added `B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_0..4`, expressed from
    `BOARD_COLUMN_BOTTOM_VISIBLE_OFFSET` and `BOARD_CELL_STRIDE`.
  - Renamed `LevelThresholds` to `GameTurnLevelStartIndexTable` and added
    `GAME_TURN_LEVEL_*_START_INDEX` constants for the ten-record level starts.
  - Synced `Yoshi/yoshi.sym`, board/data/memory notes, findings, task-plan,
    and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the table-value cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 437 / 445 items complete.

### Phase 2/5: Bank 1 Sound Sequence Rewind Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_SEQUENCE_REWIND_LOW_BYTE_DELTA` and
    `SOUND_SEQUENCE_REWIND_HIGH_BYTE_DELTA`.
  - Replaced the raw `sub $01` / `sbc $00` sequence-pointer rewind in
    `RewindSoundSequencePointerAndReturnCarry`.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sequence-rewind cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sound rewind scan shows the raw `sub $01` / `sbc $00`
    sequence-pointer rewind now uses `SOUND_SEQUENCE_REWIND_*_DELTA`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 436 / 444 items complete.

### Phase 2/5: Sound Loop Counter Reset Constant
- **Status:** completed
- Actions taken:
  - Reused `SOUND_COUNTER_INIT_VALUE` in the `$FE`
    `SOUND_LOOP_JUMP_COMMAND` counted-loop reset path.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the loop-counter cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 435 / 443 items complete.

### Phase 2/5: Bank 1 Sound Fixed Tempo And Pitch-Slide Clamp
- **Status:** completed
- Actions taken:
  - Added `SOUND_FIXED_TEMPO_HI` and `SOUND_FIXED_TEMPO_LO` for the channel-7
    fixed `$0100` tempo multiplier in `UseSfxOrFixedSoundTempo`.
  - Added `SOUND_PITCH_SLIDE_MIN_TICKS` for the one-tick clamp in
    `InitSoundPitchSlideForNote`.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the fixed-tempo/pitch-slide
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 434 / 442 items complete.

### Phase 2/5: Bank 1 Sound Register Bases And Channel 6 Pointer Offset
- **Status:** completed
- Actions taken:
  - Added `SOUND_SEQUENCE_PTR_BYTES_PER_CHANNEL` and
    `SOUND_SECONDARY_WAVE_SEQUENCE_PTR_OFFSET`.
  - Replaced the raw channel-6 sequence pointer offset in
    `StoreSoundBgmActiveState`.
  - Added `SOUND_REGISTER_CH1_BASE_LOW` through
    `SOUND_REGISTER_CH4_BASE_LOW` and used them in `SoundRegisterOffsetTable`.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound register-base cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sound scan shows the raw `SOUND_CH_SEQUENCE_PTRS + $0c`
    offset and raw `$10/$15/$1A/$1F` register-base row are now named.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 433 / 441 items complete.

### Phase 3/5: Unassigned Serial DIV Reset Value
- **Status:** completed
- Actions taken:
  - Added `SERIAL_DIV_RESET_WRITE_VALUE`.
  - Replaced the raw `ld a, $03` before the unassigned-role `rDIV` write in
    `SerialHandler`.
  - Updated link-state notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the serial DIV reset value cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 0 serial scan shows the raw `ld a, $03` write value now uses
    `SERIAL_DIV_RESET_WRITE_VALUE`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 432 / 440 items complete.

### Phase 2/5: BG Map Shadow Copy Phase Values
- **Status:** completed
- Actions taken:
  - Added `BG_MAP_COPY_PHASE_SLICE_0`,
    `BG_MAP_COPY_PHASE_SLICE_1`, and `BG_MAP_COPY_PHASE_SLICE_2`.
  - Replaced the raw phase-2 value in `CopyNextBgMapShadowSlice`.
  - Updated VRAM-copy notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the BG-map copy phase cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 BG-map copy scan shows the raw `ld a, $02` phase value now
    uses `BG_MAP_COPY_PHASE_SLICE_2`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 431 / 439 items complete.

### Phase 4/5: Unused Inline Egg Text Tile Constants
- **Status:** completed
- Actions taken:
  - Added `EGG_TEXT_FRAME0_TILE_BASE`,
    `EGG_TEXT_INLINE_TWO_TILE_ROW_DELTA`, and
    `EGG_TEXT_INLINE_THREE_TILE_ROW_DELTA`.
  - Replaced raw `$F0-$FA` tile IDs and `$0013/$0012` row advances in
    `UnusedInlineEggTextFrame0Drawer`.
  - Reused the same tile-base expression in `EggTextFrame0TileRows` and the
    shared `$F0-$F4` rows in `EggTextFrame2TileRows`.
  - Updated egg-counter notes, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the egg-text tile cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 430 / 438 items complete.

### Phase 5/5: Sprite Object Renderer Scan End Offset
- **Status:** completed
- Actions taken:
  - Added `SPRITE_OBJECT_SCAN_END_OFFSET`.
  - Replaced the raw low-byte wrap comparison in `UpdateSprites`.
  - Updated sprite/OAM notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sprite scan-end offset cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sprite scan-end scan shows the raw `cp $00` comparison now
    uses `SPRITE_OBJECT_SCAN_END_OFFSET`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 430 / 438 items complete.

### Phase 2/5: Bank 1 Sound Hardware Reset Values
- **Status:** completed
- Actions taken:
  - Added `SOUND_HW_RESET_ENABLE_VALUE`,
    `SOUND_HW_RESET_SWEEP_ENV_VALUE`,
    `SOUND_HW_RESET_LENGTH_ON_VALUE`,
    `SOUND_HW_RESET_ZERO_CLEAR_BYTES`, and
    `SOUND_HW_RESET_COUNTER_CLEAR_BYTES`.
  - Replaced raw sound hardware reset values and full-reset clear spans in
    `StopAllSoundHW`, the BGM reset tail, and the channel-entry expansion
    NR10 reset.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the hardware reset cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sound reset scan shows no remaining raw `ld a, $80`,
    `ld a, $40`, `ld a, $08`, `ld d, $a0`, or `ld d, $18`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 428 / 436 items complete.

### Phase 2/5: Bank 1 Sound BGM Reset Bounds
- **Status:** completed
- Actions taken:
  - Added `SOUND_BGM_RESET_SKIP_MAX_COMMAND`,
    `SOUND_BGM_RESET_MAX_COMMAND`, and
    `SOUND_PRIMARY_POINTER_CLEAR_BYTES`.
  - Replaced raw SoundEngine command-bound comparisons and the BGM reset path's
    primary pointer/channel clear spans.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the BGM reset bound cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 427 / 435 items complete.

### Phase 2/5: Bank 1 Sound BGM Active-ID Gate
- **Status:** completed
- Actions taken:
  - Added `SOUND_BGM_ACTIVE_ID_GATE`.
  - Replaced the shared raw `cp $0f` gate in `ClearSoundChannelAfterEnd`,
    `UpdateChannel`, `SoundLookupIndex`, and `StartSoundSequence`.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the BGM active-ID gate cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sound scan shows no remaining raw `cp $0f` comparisons.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 427 / 435 items complete.

### Phase 2/5: Bank 1 Sound Pitch Shift Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_PITCH_SHIFT_TARGET_OCTAVE` and
    `SOUND_PITCH_FREQ_HIGH_BIAS`.
  - Replaced the raw `cp $07` and `ld a, $08` inside `SoundUpdate5`, the
    pitch-table helper used by note and pitch-slide setup.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the pitch shift cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 425 / 433 items complete.

### Phase 2/5: Bank 1 Sound Note-Length And Wave-Pattern Parameters
- **Status:** completed
- Actions taken:
  - Added `SOUND_NOTE_LENGTH_SEQUENCE_STEP_VALUE`,
    `SOUND_WAVE_PATTERN_LAST_BYTE_INDEX`, and
    `SOUND_WAVE_LEVEL_PARAM_BITS`.
  - Replaced the raw note-length parser step comparison in `TickSoundChannel`,
    the wave-level parameter mask in the length/envelope parser, and the
    selected wave-pattern copy-loop seed in `ProcessNote`.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound note-length and
    wave-pattern parameter cleanup and rebuilt `Yoshi/game.gb` byte-identical
    to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sound scan shows the touched raw `cp $01`, `and $30`, and
    `ld b, $0f` literals now use `SOUND_*` constants.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 424 / 432 items complete.

### Phase 2/5: Bank 1 Sound Pause And Wave Hardware Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_PAUSE_MUTE_APPLIED_BIT`,
    `SOUND_REST_ENVELOPE_VALUE`, and
    `SOUND_FREQ_HIGH_RESTART_KEEP_MASK`.
  - Replaced high-confidence raw Bank 1 sound hardware literals with
    `AUD3ENA_ON`, `AUD3ENA_OFF`, `AUDHIGH_RESTART`, and the new scoped
    sound constants in the pause, wave-channel reset, rest, wave-pattern copy,
    and note-trigger paths.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound hardware constant
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 424 / 432 items complete.

### Phase 2/5: Bank 1 Sound Vibrato And Register Offset Constants
- **Status:** completed
- Actions taken:
  - Added scoped sound constants for packed vibrato phase/depth masks,
    NRx1 duty bits, low-six length bits, and the `SoundUpdate3`
    NRx1/NRx2/NRx3 register offsets.
  - Replaced the matching raw masks and `ld b, $01/$02/$03` register-offset
    immediates in the Bank 1 sound vibrato, note-output, rest, pitch-slide,
    and duty-rotate paths.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound mask/offset cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 1 sound scan found no remaining raw `and $0f/$f0/$c0/$3f`
    or `ld b, $01/$02/$03` in the touched paths.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 421 / 429 items complete.

## Session: 2026-05-30

### Status Check And Verification
- **Status:** completed
- Actions taken:
  - Confirmed branch `yoshi-disassembly-step6`.
  - Confirmed the active uncommitted source diff is the piece display object
    `$28` rename from base-Y to initial delay, plus matching docs/plan updates.
  - Left unrelated untracked local files `AGENTS.md` and `CLAUDE.md` untouched.
  - Ran the standard Yoshi verifier after the rename.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.

### Phase 2/5: Score Preserve And Copy-Only WRAM Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked `$C620/$C628/$C629/$C672` after the final raw WRAM cleanup.
  - Confirmed `$C620` is set by `ResetTitleState` and only preserved/restored
    while `ResetScoreAccumulatorAndDigits` clears the adjacent score range.
  - Confirmed `$C672` is seeded with `$30` by
    `InitBTypeFallTimingAndBoardSeed`; `AddScore` copies it to `$C629` and
    writes its swapped form to `$C628`, with no confirmed independent consumer.
  - Renamed the former score-adjacent unknown constants to
    `SCORE_PRESERVED_UNUSED_BYTE` and `SCORE_UNUSED_TILE_BASE_*`, keeping them
    low confidence.
  - Updated memory-map, confidence/open-question, checklist, estimate, and
    task-plan notes to match the narrower names.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the score preserve/copy-only
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4/5: Sprite Slot Toggled Frame And Fast-Fall Clamp Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked logical sprite object slot bytes `+$01`, `+$03`, and `+$0F`
    across `UpdateSprites`, `UpdateSpriteObject`, the option BGM cursor update,
    and the Down-held fast-fall clamp path.
  - Confirmed `+$01` is skipped by OAM expansion and has no independent
    consumer in the current trace, so it remains unused/padding.
  - Added `SPRITE_OBJECT_TOGGLED_FRAME`, `BGM_CURSOR_OBJECT_SLOT_BASE`, and
    `BGM_CURSOR_FRAME_TOGGLE_MASK` for the BGM option cursor frame toggle path.
  - Added `SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE` for the low-confidence `+$0F`
    byte that is only clamped by `ClampGameplayObjectFastFallLoop`.
  - Updated sprite/OAM, fall-timing, open-question, checklist, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sprite slot cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4: Reserved Sprite Object Type 7 Cleanup
- **Status:** completed
- Actions taken:
  - Traced sprite object type `$07` from `SpriteUpdatePointerTable` through its
    frame table, tile list, and layout.
  - Searched current source for a producer that writes `$07` as a logical
    sprite object type; none was confirmed.
  - Renamed the type `$07` frame entry to `SpriteFrameTable_ReservedObject7`,
    with matching reserved tile-list and layout labels.
  - Added `SPRITE_OBJECT_TYPE_RESERVED_7` as a narrow constant documenting that
    the frame table exists but the producer is not confirmed.
  - Updated sprite/OAM, data-ranges, open-question, checklist, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the reserved object type cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4: High-Bit Sprite Object Variant Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked `UpdateSprites` and all current `SPRITE_OBJECTS_HI` producer
    contexts for high-bit logical sprite object type writes.
  - Confirmed `UpdateSprites` saves type bit `$80` to
    `SPRITE_OBJECT_ATTR_TMP`; for valid values `$81-$87`, `dec` + `sla` drops
    bit 7 from the frame-table offset, so the values share `$01-$07` frame
    tables while providing an inherited OAM attribute bit.
  - Confirmed the current `set 7` / `res 7` / `or $80` source hits are LCD,
    sound, or link-result state, not logical sprite object type producers.
  - Replaced the remaining game-over sequence raw object type `$02` write with
    the piece-display object type constant.
  - Updated sprite/OAM, open-question, checklist, findings, estimate, and
    task-plan notes to remove the stale high-bit indexing wording.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the high-bit sprite object
    variant cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`; both SHA-256 values are
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct branch, generated local label, targeted stale-name,
    and `git diff --check` scans passed.

### Phase 5: Landing Placement Sound And Score Delta Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked `$C69D/$C6AE/$C6BF/$C6C0` across current source, docs, and recent
    history. No hidden producer was found; `$C6BF` remains clear-then-decrement
    state in scan/landing paths, so the four `UNRESOLVED_LANDING_*` names stay
    in place.
  - Named sound ID `$1C` as `SND_PLACE_PIECE` from its only confirmed call site:
    `DrawLandedPieceAndUpdateColumnTop`, where the falling piece is drawn into
    the selected column and the column top row is lowered.
  - Added `SoundIndexEntry_PlacePiece` as the matching alias for
    `SoundIndexEntry_1c`.
  - Added `SCORE_DELTA_COMMIT_PIECE` for the packed-BCD `00005` delta passed to
    `AddScore` by `CommitFallingPieceToBoard`.
  - Updated fall-timing, sound-engine, open-question, checklist, estimate,
    findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the landing placement cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`; both
    SHA-256 values are
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct branch, generated local label, targeted stale-name,
    and `git diff --check` scans passed.

### Phase 5: UpdateMatchState Return And Row Constant Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked `UpdateMatchState`, `UpdateSpriteObject`, column-top row updates,
    and the board layout notes for remaining narrow gameplay immediates.
  - Added `SPRITE_OBJECT_UPDATE_CONTINUE` for the nonzero
    `UpdateMatchState` return that causes `UpdateSpriteObject` to write the
    staged record back.
  - Reused `BOARD_DRAW_FIRST_ROW` for the top-row game-over sequence check.
  - Added `PIECE_FALL_SPRITE_Y_STEP` for the 8-pixel staged sprite Y advance
    while a piece is still falling.
  - Added `COLUMN_TOP_ROW_OVERFLOW_SENTINEL` for the `$FF` column-top underflow
    that enters the game-over/result path after direct placement.
  - Updated board-layout, fall-timing, checklist, estimate, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the `UpdateMatchState` constant
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`;
    both SHA-256 values are
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct branch, generated local label, targeted
    `UpdateMatchState` row/Y-step/overflow stale-immediate, and
    `git diff --check` scans passed.

### Phase 4/5: Result Flow Code And Link Packet Constant Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked B-type clear, falling-piece overflow, `QueueRoundResult`,
    asynchronous link result packets, `Exchange2PResultCode`,
    `CalcRankPosition`, and the 2P result mark counter path.
  - Added `RESULT_FLAG_SET` for result/high-score flags that are explicitly
    raised with value `1`.
  - Added `ROUND_RESULT_CODE_ZERO` and `ROUND_RESULT_CODE_NONZERO` for the
    queued values passed through `ROUND_RESULT_CODE` to `ProcessRoundResultAndEnterRoundEnd`.
  - Added `LINK_RESULT_PACKET_FLAG`, `LINK_RESULT_PACKET_BIT`, and
    `LINK_RESULT_CODE_BIT` for bit-7 result packets and the bit-0 result-code
    payload.
  - Added `LINK_FIELD_COUNT_PACKET_BIT` and `LINK_FIELD_EVENT_BIT` for the
    adjacent bit-5 field-count packets and bit-6 field-rise packets handled by
    the same link dispatch path.
  - Added `LINK_RESULT_MARK_LIMIT` for the three-mark terminal 2P result panel
    threshold, and `RESULT_RANK_FIRST_PLACE` for the equal-result master-side
    rank return.
  - Updated link-state, result-record, fall-timing, memory-map, estimate, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the source edits and rebuilt
    `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4/5: Grid Piece Draw Footprint Constant Cleanup
- **Status:** completed
- Actions taken:
  - Rechecked `DrawGridPiece`, `DrawColumnSprite`, side-column clear helpers,
    drop redraw paths, `FillInitialBoardColumns`, and
    `CommitFallingPieceToBoard` around board-cell rendering.
  - Added `GRID_PIECE_TILE_WIDTH`, `GRID_PIECE_TILE_ROWS`,
    `GRID_PIECE_NEXT_ROW_DELTA`, `GRID_DRAW_ROW_LIMIT`, and
    `GRID_COLUMN_CLEAR_TILE` for the visible 4x2 payload footprint and its
    shadow BG-map row movement.
  - Added `COLUMN_TOP_ROW_COMMIT_LIMIT` for the narrow `$10` guard in
    `CommitFallingPieceToBoard`.
  - Replaced local row/clear immediates in the grid draw and drop redraw paths,
    and reused `COLUMN_COUNT` / `BOARD_COLUMN_STRIDE` in the initial board fill
    loop.
  - Updated board-layout, drop-animation, memory-map, checklist, estimate,
    findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the source edits and rebuilt
    `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4/5: Field Column Sprite Object Recovery
- **Status:** in_progress
- Actions taken:
  - Traced sprite object type `$06` from the old `UpdateBoard` label through
    slots 10-13, `FIELD_COLUMN_TIMERS`, `UpdateFieldTimers`, and the Bank 1
    sprite frame table.
  - Renamed `UpdateBoard` to `SpawnFieldColumnEffect` because the routine
    creates a timed logical sprite object rather than updating board storage.
  - Added `SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT` and
    `FIELD_COLUMN_EFFECT_SLOT_BASE`, and separated the slot-base constant from
    the timer reload constant that happens to share value `$0A`.
  - Rechecked sprite slot byte `+$0F`; at this checkpoint the only confirmed
    reference was the Down-held fast-fall clamp in `HandlePlayfieldInput`.
  - Renamed the object `$06` frame/tile/layout table labels in `bank_001.asm`.
  - Updated `Yoshi/yoshi.sym`, `Yoshi/ARCHITECTURE.md`, sprite/OAM,
    field-animation, board-layout, data-range, and memory map notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the field-column effect rename
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 5: Board Bottom Visible Cell Recovery
- **Status:** in_progress
- Actions taken:
  - Traced raw `$C637` references in `AnimateDropping` and
    `FillInitialBoardColumns`.
  - Identified the address as `BOARD_DATA + $0D`, the bottom visible odd cell
    of the first 16-byte board column block.
  - Added `BOARD_COLUMN_BOTTOM_VISIBLE_OFFSET` and
    `BOARD_COLUMN_BOTTOM_VISIBLE_CELL`, and replaced the raw `$C637` operands.
  - Updated board layout, drop-animation, memory map, next-work, and findings
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the board bottom visible-cell
    rename and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 2/4: WRAM And Manual OAM Tail Constants
- **Status:** completed
- Actions taken:
  - Added `WRAM_START` and `WRAM_SIZE` for the startup WRAM clear loop.
  - Added `SHADOW_OAM_MANUAL_PAIR` for `$C498`, the two-entry tail used by
    `AddScoreAndAnimateManualOamPair` outside the normal `UpdateSprites` hide
    range.
  - Replaced raw `$C000`, `$2000`, and `$C498` operands in `bank_000.asm`.
  - Updated sprite/OAM, memory map, and findings notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the WRAM/manual-OAM constant
    pass and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 2/4: BG Map Shadow Slice Copy Recovery
- **Status:** completed
- Actions taken:
  - Traced `ProcessFieldLogic` in Bank 1 and confirmed it copies
    `BG_MAP_SHADOW` to BG map VRAM as one six-row slice per VBlank while
    `BG_MAP_SHADOW_COPY_ENABLE_FLAG` is nonzero.
  - Named `$FFA6` as `BG_MAP_COPY_PHASE`; it rotates through the three source
    slices `$C4A0`, `$C518`, and `$C590`.
  - Named `$FFA7/$FFA8` as `VBLANK_SAVED_SP_HI/LO`, the shared temporary SP
    save used by both pop-based VBlank copy loops.
  - Added source/destination slice constants for the shadow buffer and VRAM
    destinations `$9C00`, `$9CC0`, and `$9D80`.
  - Documented the 20-byte shadow-row stride versus the 32-byte hardware BG
    map row stride in `docs/source_recovery/vram_copy.md`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the BG map shadow slice-copy
    recovery and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4/5: 2P Result Mark Tilemap Origins
- **Status:** completed
- Actions taken:
  - Traced `UpdateLinkResultMarksAndScreen`'s 2P result panel mark drawing.
  - Named the six 2x2 mark boxes cleared with tile `$14` and filled with tile
    `$10`.
  - Added `LINK_RESULT_NONZERO_MARK_BASE` at `$C4F3` for marks drawn rightward
    from `LINK_RESULT_NONZERO_MARKS`.
  - Added `LINK_RESULT_ZERO_MARK_BASE` at `$C4FF` for marks drawn leftward
    from `LINK_RESULT_ZERO_MARKS`.
  - Updated link-state, memory-map, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the 2P result mark tilemap
    origin recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 89
    occurrences across 60 distinct addresses.

### Phase 2: SCY/WY Shadow HRAM
- **Status:** completed
- Actions taken:
  - Confirmed `$FF9D` and `$FF9E` sit beside the existing `SCX_SHADOW` path.
  - Startup initializes `$FF9D` to zero and `$FF9E` to `$90`.
  - Bank 1 VBlank copies `$FF9D` to `rSCY` and `$FF9E` to `rWY`.
  - Added `SCY_SHADOW` and `WY_SHADOW`, and replaced the remaining raw HRAM
    references.
  - Updated memory-map, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the SCY/WY shadow HRAM naming
    pass and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.

### Phase 4: Wave RAM And Countdown Blit Destinations
- **Status:** completed
- Actions taken:
  - Replaced Bank 1 raw `$FF30` wave RAM writes with the existing hardware
    constant `_AUD3WAVERAM`.
  - Documented that the wave-channel note path disables NR30, writes the
    selected 16-byte wave pattern to `$FF30-$FF3F`, then re-enables the wave
    channel.
  - Added `COUNTDOWN_BLIT_DEST_PHASE0` (`$9020`) and
    `COUNTDOWN_BLIT_DEST_PHASE1` (`$9120`) for the countdown digit buffer
    blits in `RandomNext`.
  - Updated sound-engine, countdown-buffer, memory-map, findings, and task-plan
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the wave RAM/countdown VRAM
    destination recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.

### Phase 4: Graphics VRAM Destinations And Matching OAM Entries
- **Status:** completed
- Actions taken:
  - Added project-local VRAM destination constants based on `_VRAM` and
    `_SCRN1`, avoiding the deprecated `_VRAM8000` helper names from
    `hardware.inc`.
  - Replaced raw graphics-copy destinations for Bank 2/3 tile loads with
    `VRAM_TILE_BLOCK_8000`, `VRAM_TILE_BLOCK_8800`,
    `VRAM_TILE_BLOCK_9000`, and specific 2P/high-score/title-result
    destination constants.
  - Replaced the startup VRAM clear start/size with `VRAM_START` and
    `VRAM_SIZE`.
  - Added OAM entry field offsets and `SHADOW_OAM_ENTRY_*` constants for the
    matching/result animation's direct OAM template copies and X/tile edits.
  - Updated graphics-load, data-range, sprite/OAM, findings, and task-plan
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the VRAM/OAM destination
    recovery and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 81
    occurrences across 54 distinct addresses.

### Phase 4/5: Round-Complete Tilemap Origins
- **Status:** completed
- Actions taken:
  - Traced the four raw tilemap origins `$C5B9/$C5BD/$C5C1/$C5C5` through the
    round-complete display path.
  - Added `ROUND_COMPLETE_TILEMAP_ORIGIN_0..3` for the four 2x2 tilemap boxes.
  - Added tile and rectangle constants for the pending, reveal, and clear
    stages handled by `ShowRoundComplete`.
  - Documented the relation between the four tilemap boxes and the sprite
    groups emitted by `ProcessRoundComplete` at base X `$10/$30/$50/$70`.
  - Updated memory-map, sprite/OAM, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the round-complete tilemap
    origin recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 73
    occurrences across 50 distinct addresses.

### Phase 4/5: Result Record Row Tilemap Origins
- **Status:** completed
- Actions taken:
  - Traced the result record display setup and `DrawStoredResultRecords`
    renderer.
  - Added `RESULT_RECORD_LABEL_ORIGIN_0..2` for the three 3-tile row labels at
    `$C52D/$C555/$C57D`.
  - Added selected/normal label tile constants used by
    `WaitResultRecordScreenInput` while blinking the selected result row.
  - Added `RESULT_RECORD_VALUE_TOP_LEFT` and the three placeholder origins
    `$C534/$C538/$C53D` seeded before stored records are rendered.
  - Renamed the misleading Bank 0 `NextRound` helper to
    `FillResultRecordPlaceholderColumn`.
  - Updated `Yoshi/yoshi.sym`, result-record, memory-map, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the result record row tilemap
    recovery and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 63
    occurrences across 43 distinct addresses.

### Phase 4/5: 2P Result Layout Tilemap Origins
- **Status:** completed
- Actions taken:
  - Traced `UpdateLinkResultMarksAndScreen`,
    `DrawLinkResultRoleStatusStrip`, and the terminal 2P result
    branch around the remaining repeated `$C4xx/$C5xx` BG-map origins.
  - Added `LINK_RESULT_LEFT/RIGHT_HEADER_TOP_LEFT` for `$C4CD/$C4D3` and
    `LINK_RESULT_LEFT/RIGHT_BADGE_TOP_LEFT` for `$C4B7/$C4C3`.
  - Added `LINK_RESULT_OUTCOME_LEFT/RIGHT_TOP_LEFT` for `$C572/$C574`.
  - Added `LINK_RESULT_STATUS_TOP_LEFT` and
    `LINK_RESULT_BOTTOM_TEXT_TOP_LEFT` for `$C5D0/$C5D7`, plus local rectangle
    size constants.
  - Replaced the scoped raw operands in `Yoshi/bank_000.asm` and updated
    link-state, memory-map, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the 2P result layout origin
    recovery and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 48
    occurrences across 35 distinct addresses.

### Phase 4: Title Screen BG Layout Origins
- **Status:** completed
- Actions taken:
  - Traced `InitTitleUI` fixed rectangle fills in `BG_MAP_SHADOW`.
  - Added title frame/panel/strip origin constants for
    `$C4B1/$C4B5/$C4C5/$C507/$C510/$C575`.
  - Added matching rectangle-size constants and replaced the raw operands in
    `Yoshi/bank_000.asm`.
  - Updated title menu, memory-map, findings, task-plan, checklist, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the title screen BG layout
    origin recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 42
    occurrences across 30 distinct addresses.

### Phase 4/5: 2P Field Occupancy Count Path
- **Status:** completed
- Actions taken:
  - Traced the repeated `$C4C8` scan used by `InitTitleGfx` and the 2P gameplay
    path.
  - Renamed `CalcDifficulty` to `QueueLinkFieldOccupancyCount`, because it
    counts non-empty field-display tiles and queues `count | $20`.
  - Renamed `ProcessBit7` to `ProcessLinkFieldCountPacket` and `SpeedTable` to
    `DrawTwoDigitLinkFieldCount`.
  - Added constants for the 7x4 field occupancy scan, empty tile `$4A`, packet
    flag `$20`, local count digits `$C565-$C566`, and peer count digits
    `$C5DD-$C5DE`.
  - Updated `Yoshi/yoshi.sym`, link-state, memory-map, findings, task-plan,
    checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the 2P field occupancy count
    path recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 37
    occurrences across 26 distinct addresses.

### Phase 4/5: Result Record Screen Setup Layout
- **Status:** completed
- Actions taken:
  - Traced the result record screen setup immediately before
    `DrawStoredResultRecords`.
  - Added BG-map origin constants for the header, type label, frame, column
    header, B-type header patch, A-type detail panels, B-type detail panel, and
    B-type mark block.
  - Renamed the row-frame helper to `FillResultRecordBoxRow`, separating it
    from the placeholder-column helper used by the record rows.
  - Updated `Yoshi/yoshi.sym`, result-record notes, memory map, findings,
    task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the result record screen setup
    layout recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 27
    occurrences across 17 distinct addresses.

### Phase 4/5: A-Type Round-Complete Summary Layout And Data
- **Status:** completed
- Actions taken:
  - Traced the A-type-only round-complete summary path after the result wait.
  - Renamed `InitAnimFrame` to `ShowATypeRoundCompleteSummary`.
  - Added layout constants for the summary header strip, panel, and 12-byte
    message destination at `$C4B4/$C544/$C56A`.
  - Converted the fake-code island at `00:$3799-$37DF` into three 12-byte
    summary messages, the seven-byte final-tile table, and the seven-record
    reveal-threshold table used by `ShowRoundComplete`.
  - Updated `Yoshi/yoshi.sym`, data-range notes, memory map, sprite/OAM notes,
    findings, task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the A-type round-complete
    summary layout/data recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 24
    occurrences across 14 distinct addresses.

### Phase 4/5: Matching And Link Result Animation Layout Origins
- **Status:** completed
- Actions taken:
  - Traced remaining result/link layout-style raw `$Cxxx` references.
  - Added matching animation layout constants for the intro blink block
    (`$C4ED`), three-tile animation strip (`$C59B`), and final result header
    (`$C4CA`).
  - Added link result confirmation layout constants for the 6x6 wait panel
    (`$C543`) and non-master detail block (`$C571`).
  - Updated link-state notes, memory map, findings, task-plan, checklist, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the matching/link result layout
    origin recovery and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 18
    occurrences across 9 distinct addresses.

### Phase 2/5: Final Raw WRAM Reference Labeling
- **Status:** completed
- Actions taken:
  - Rechecked the final raw `$Cxxx` references after the layout cleanup.
  - Confirmed `$C620/$C628/$C629/$C672` still have no independent consumer:
    `$C620` is preserved across score clearing, and `$C672` is copied/swapped
    into `$C629/$C628` by `AddScore`.
  - Confirmed `$C69D/$C6AE/$C6BF/$C6C0` remain landing/scan-adjacent state:
    the counter is decremented by scan/landing paths, while the reset bytes and
    reset timer have no confirmed consumer.
  - Replaced the final raw WRAM operands with explicitly unresolved symbolic
    constants so source code carries the current evidence without hiding the
    uncertainty.
  - Updated memory-map, fall-timing, confidence/open-question, findings,
    task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the final raw WRAM reference
    labeling and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` are now 0.

### Phase 4/5: Bank 0 Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Traced the old Bank 0 `DrawString`, `DrawNumber`, and `DrawCharacter`
    helpers.
  - Renamed `DrawString` to `WaitVBlankFrames` because it only waits `C`
    VBlanks.
  - Renamed `DrawNumber` to `ShiftMatchingOamPairX` because it adjusts the X
    fields of two matching/result OAM entries by `C`; the unrelated
    `$1203` rectangle-size use was split into `WIN_SCREEN_RIGHT_PANEL_RECT_SIZE`.
  - Renamed `DrawCharacter` to `FillBytesWithD` because it fills `BC` bytes
    from `HL` with the value in `D`.
  - Renamed `SetupDrawCharacter` to `ClearManualOamPair`.
  - Renamed `DrawDigit` to `ReloadGameTilesAndRequestRedraw`.
  - Renamed `WaitFrames` to `WaitFramesSetTransitionOnInput`.
  - Updated `Yoshi/yoshi.sym`, architecture notes, findings, task-plan, and
    checklist.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the helper label cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 4/5: Round-Complete Reveal Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Traced the `ShowRoundComplete` reveal branches and the helper block at
    `00:$3767-$380F`.
  - Renamed the 2x2, 3x2, and 3x4 rectangle helpers to
    `RevealRoundComplete2x2Block`, `RevealRoundComplete3x2Block`, and
    `RevealRoundComplete3x4Block`.
  - Renamed the manual sprite helper to `AddScoreAndAnimateManualOamPair`
    because it calls `AddScore`, stages two entries in
    `SHADOW_OAM_MANUAL_PAIR`, moves both Y fields upward for 16 frames, then
    waits 30 frames.
  - Updated `Yoshi/yoshi.sym`, architecture notes, findings, sprite/OAM notes,
    data-range notes, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the round-complete helper label
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.
  - `git diff --check` passed.

### Phase 5: Elapsed Timer Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Traced the Bank 1 elapsed-timer helpers around `01:$49E8-$4A20`.
  - Renamed the `01:$49E8` helper to `DrawRoundTimerDigits`; it draws
    `ROUND_TIMER_DIGITS` to the current tilemap coordinate when not in 2P mode.
  - Renamed the `01:$4A09` helper to `ClearRoundTimerDigitsAndResume`; it
    clears the four round-timer display digits and clears `ROUND_TIMER_STOPPED`.
  - Renamed the `01:$4A15` helper to `ClearTotalTimerDigitsAndResume`; it
    clears the four total-timer display digits and clears `TOTAL_TIMER_STOPPED`.
  - Updated `Yoshi/yoshi.sym`, memory-map notes, findings, task-plan,
    checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the elapsed-timer helper label
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 4/5: Link Round-State Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Traced the old egg-named Bank 1 helper at `01:$46BD`.
  - Renamed it to `ClearLinkRoundState` because it clears
    `LINK_SEND_QUEUE_INDEX`, `LINK_PENDING_FIELD_RISE`, `LINK_SEND`,
    `LINK_RECV`, `LINK_UNUSED_STAGING_BYTE`, both link send queue slots, and
    `LINK_FIELD_EVENT_PAYLOAD`.
  - Updated `Yoshi/yoshi.sym`, link-state notes, memory-map notes, findings,
    task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the link helper label cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 4/5: Sprite Cursor And Tilemap Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the slot-0 cursor initializer at `01:$44D0` to
    `InitPlayerCursorObject`; it initializes `FIELD_COLUMN_TILE_PATTERN_INDEX`
    and writes the slot-0 `SPRITE_OBJECT_TYPE_PLAYER_CURSOR` record.
  - Renamed the `01:$44EA` helper to `FillTilemapRectByCoord` because it
    converts a packed row/column coordinate through `CalcTilemapAddress` and
    fills a `B` by `C` rectangle with tile `A`.
  - Renamed the `01:$4501` helper to `DrawSequentialTileRowByCoord` because it
    converts the coordinate and writes `B` consecutive tile IDs starting at `C`.
  - Updated `Yoshi/yoshi.sym`, architecture notes, sprite/OAM notes, memory-map
    notes, findings, task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the cursor/tilemap helper label
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 4/5: Sprite Buffer And Playfield HUD Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `01:$4854` helper to `ClearSpriteObjectBuffer`; it clears
    `$FF` bytes from `SPRITE_OBJECTS` before playfield UI and sprite producers
    rebuild the logical object slots.
  - Renamed the `01:$45C2` wrapper to `DrawEggTextFrame0`; it sets frame `0`
    before jumping into `DrawEggTextFrameByIndex`.
  - Renamed the playfield HUD helpers at `01:$489A`, `01:$48B7`, and
    `01:$48DF` to `DrawPlayfieldLevelDigits`,
    `DrawPlayfieldSpeedValue`, and `DrawPlayfieldEggDisplay`.
  - Updated `Yoshi/yoshi.sym`, sprite/OAM notes, memory-map notes, egg counter
    notes, findings, task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sprite buffer/playfield HUD
    helper label cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both files remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 4/5: Playfield Timer And Link Header Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `01:$4976` helper to `DrawBTypeTimerHeaderAndDigits`; it
    draws the 1P B-TYPE timer header row and then draws the round timer digits.
  - Renamed the `01:$498D` wrapper to `DrawPlayfieldRoundTimerDigits`; it fixes
    `DrawRoundTimerDigits` to the playfield row 6/column 16 coordinate.
  - Renamed the `01:$49B6` helper to `DrawTwoPlayerPlayfieldRoleHeaders`; it
    draws two 2P role header rows and swaps their tile rows when `LINK_ROLE` is
    `LINK_ROLE_SLAVE`.
  - Added constants for the playfield timer/header packed coordinates, tile
    rows, and `LINK_ROLE_SLAVE`.
  - Updated `Yoshi/yoshi.sym`, memory-map notes, link-state notes, findings,
    task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the playfield timer/link header
    helper cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - The previous numbered placeholder labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 4/5: Playfield Side-Panel Layout Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `01:$485F` helper to `Draw1PPlayfieldSidePanelLabelRow0`; it
    skips 2P mode and draws the row-0 side-panel label at the A-type or B-type
    coordinate.
  - Renamed the shared `01:$4873` row-draw target to
    `DrawPlayfieldSidePanelLabelRow0AtCoord`.
  - Renamed the `01:$487A` helper to `DrawPlayfieldSidePanelLabelRow1`; it
    chooses the 2P, A-type, or B-type row-1 side-panel label coordinate.
  - Renamed the `01:$48FB` helper to `DrawPlayfieldBottomColumnMarkers`; it
    writes four repeated `$FB/$FC` tile pairs along row 16.
  - Renamed the mode-specific blank-row helpers at `01:$491F`, `01:$4938`,
    and `01:$495D` to `BlankATypePlayfieldSidePanelRows`,
    `BlankBTypePlayfieldSidePanelRows`, and
    `BlankTwoPlayerPlayfieldSidePanelRows`.
  - Added constants for the playfield side-panel rectangle, label rows, bottom
    marker tiles, and mode-specific blank row coordinates.
  - Updated `Yoshi/yoshi.sym`, board-layout notes, findings, task-plan,
    checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the playfield side-panel layout
    helper cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - The previous numbered placeholder labels and old column-block helper name
    no longer appear in source, symbols, or recovery docs.
  - Raw `$Cxxx` references and raw direct branch operands in
    `bank_000.asm` / `bank_001.asm` remain at 0.

### Phase 5: Egg Text Animation Symbol Sync
- **Status:** completed
- Actions taken:
  - Updated `Yoshi/yoshi.sym` so the Bank 1 egg text animation entry points use
    the same recovered names already present in `Yoshi/bank_001.asm`:
    `StartEggTextPulse`, `UpdateEggTextAnimation`,
    `ToggleEggTextAltAnimation`, and `EnableEggTextAltAnimation`.
  - Updated egg counter notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the symbol-file sync and rebuilt
    `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - The stale placeholder names for these egg text animation entries no longer
    appear in source, symbols, or recovery docs.

### Phase 5: Gameplay Input And Fall Delay Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the Bank 0 frame input helper to `HandlePlayfieldInput` because it
    handles cursor left/right input, A/B drop-start acceptance, and
    Down-held fast-fall clamping; matching/landing updates remain in
    `UpdateMatchState`.
  - Renamed the fall-delay table getter to `GetLevelFallDelay` because it caps
    `PROGRESSION_LEVEL` and indexes `LevelFallDelayTable`.
  - Renamed the piece-display remaining-count helper to
    `DecrementPieceDisplayRemaining` because it only decrements
    `PIECE_DISPLAY_REMAINING`.
  - Updated `Yoshi/yoshi.sym`, fall-timing, drop-animation, link-state,
    sprite/OAM, memory-map, piece-display, data-range, findings, task-plan,
    checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the gameplay input/fall-delay
    helper cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - The previous helper names no longer appear in source, symbols, or recovery
    docs.

### Phase 5: Playfield Board And Piece Setup Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the Bank 0 setup routine called from Bank 1 playfield init paths to
    `InitPlayfieldBoardAndPieceState`; it clears sprite slots, resets board and
    piece display state, and branches into A/B-type setup paths.
  - Renamed the slot clear helper to `ClearPieceSpriteObjectSlots`; it clears
    logical sprite object slots 1-8.
  - Renamed the round/result/landing reset helper to
    `ClearRoundLandingAndResultState`.
  - Renamed the B-type setup helper to `InitBTypeFallTimingAndBoardSeed`; it
    initializes fall delay, display count, board seed, score-adjacent unknown
    tile base, and fall acceleration timer.
  - Renamed the initial board-fill helpers to
    `FillInitialBoardWithVBlankWait` and `FillInitialBoardColumns`.
  - Updated `Yoshi/yoshi.sym`, board-layout notes, fall-timing notes,
    memory-map notes, piece-display notes, findings, task-plan, checklist, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the playfield board/piece setup
    helper cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - The previous setup helper names no longer appear in source, symbols, or
    recovery docs.

### Phase 5: Selected-Column Piece Staging Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the selected-column row helper to `GetSelectedColumnTopRow`; it
    indexes `COLUMN_TOP_ROWS` by `FALLING_PIECE_GRID_COLUMN`, returns the selected row,
    and leaves `HL` on the selected row entry for callers that update it.
  - Renamed the staged board-write helper to
    `StagePiecePayloadInSelectedColumn`; it decrements
    `PIECE_DISPLAY_REMAINING`, reads the selected column/row board cell into
    `B`, and writes the staged tile/piece payload one
    `BOARD_ADJACENT_VISIBLE_CELL_DELTA` step before that selected cell.
  - Renamed the current gameplay sprite object cleanup helper to
    `ClearCurrentGameplaySpriteObjectRecord`; it uses
    `SPRITE_OBJECT_STAGING_INDEX` to clear the selected 10-byte gameplay object
    record after commit, scan, or landing completion.
  - Updated `Yoshi/yoshi.sym`, board-layout, column-state, sprite/OAM,
    memory-map, piece-display, findings, task-plan, checklist, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - The previous movement-style helper labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.

### Phase 5: Board Scan Target Row Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the board scan row finder to `FindBoardScanTargetRow`; it starts
    at `PIECE_FALL_POS`, walks the selected board column in two-byte row
    increments, and returns the found row only when it sees
    `BOARD_SCAN_TARGET_PAYLOAD`.
  - Renamed the board cell reader to `ReadBoardCellAtColumnRow`; it computes
    `BOARD_DATA + column * BOARD_COLUMN_STRIDE + row` from `L` and `H` and
    returns the cell byte.
  - Updated `Yoshi/yoshi.sym`, board-layout notes, memory-map notes, findings,
    task-plan, checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - The previous timer/speed-style helper labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.

### Phase 4: Sound Command And Pitch-Slide Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the Bank 1 sound sequence parser dispatch labels to
    `DispatchSoundNonEndCommand`, `CheckSoundLoopJumpCommand`,
    `CheckSoundLengthEnvelopeCommand`, and `CheckSoundExtendedCommand`.
  - Renamed the pitch-slide helpers to `UpdateSoundPitchSlide`,
    `UpdateSoundPitchSlideDescending`, `ClearSoundPitchSlideFlags`, and
    `InitSoundPitchSlideForNote`.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, findings, task-plan,
    checklist, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - The previous anonymous sound dispatch and pitch-slide helper labels no
    longer appear in source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.

### Phase 5: Drop Animation Cascade Loop Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the down-cascade loop and slot-advance labels in `AnimateDropping`
    to `AnimateDropDownCascadeLoop` and `AdvanceDropDownCascadeSlot`.
  - Renamed the up-cascade loop and slot-advance labels to
    `AnimateDropUpCascadeLoop` and `AdvanceDropUpCascadeSlot`.
  - Updated drop-animation notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - The previous anonymous drop-cascade jump labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.

### Phase 3/4/5: Bank 0 Local Control Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed local startup/control labels whose behavior is clear without
    assigning broader subsystem intent:
    `CopyOAMDMARoutineToHRAMLoop`, `StoreDisabledLCDCAndRestoreIE`,
    `CheckPauseAllowedForLinkMaster`, `CheckPersistMagicByte1`,
    `ClearColumnLeftNextTilemapPage`, `UpdateFieldAnimSlot11BaseY`, and
    `HandleSinglePlayerRoundCompleteFlow`.
  - Updated VRAM/OAM copy notes, field-animation notes, findings, task-plan,
    and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - The previous targeted Bank 0 anonymous labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.

### Phase 3/4: Final Anonymous Jump Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the final anonymous `Jump_*` labels in Bank 0/1 real code:
    `ResetJoypadStateAndReinitOnRelease`, `MultiplyAddCarryChain`, and
    `ExpandSoundIndexChannelEntryLoop`.
  - Updated joypad memory-map notes, sound-engine notes, findings, task-plan,
    and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - `rg -n '^Jump_|\\bJump_[0-9]{3}_[0-9a-f]{4}\\b'
    Yoshi/bank_000.asm Yoshi/bank_001.asm docs/source_recovery/*.md
    findings.md progress.md task_plan.md` returns no matches.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.

### Phase 4/5: Result Record Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the result-record staging, ranking, insertion, and screen setup
    local labels by behavior:
    `CopyATypeEggCountRemainingDigits`, `CopyBTypeResultTimerDigits`,
    `MaskCurrentResultRecordDigits`, `MaskCurrentResultRecordDigitsLoop`,
    `BeginResultRecordInsertScan`, `ScanResultRecordInsertPositionLoop`,
    `CompareBTypeResultTimerDigits`, `AdvanceResultRecordScanSlot`,
    `InsertCurrentResultRecordAtRank`, `ShiftBTypeResultRecordsForInsert`,
    `CopyCurrentResultRecordToRankSlot`, `SetupResultRecordScreen`, and
    `FillResultRecordBoxBodyRows`.
  - Updated the symbol file, result-record notes, graphics-load map, findings,
    task plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - The targeted previous result-record local labels no longer appear in
    source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - Bank 0/1 still have 665 generated local label definitions remaining.

### Phase 4/5: Result Record Rendering Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the remaining result-record screen rendering helpers and loops by
    behavior: `DrawBTypeResultRecordDetailLayout`,
    `RenderStoredResultRecords`, `RenderBTypeResultRecords`,
    `WaitResultRecordScreenInput`, `BlinkResultRecordLabelLoop`,
    `DrawResultRecordLabelBlinkState`, `PollResultRecordBlinkInput`,
    `FillResultRecordPlaceholderColumnLoop`, `CompareResultRecordBytes`,
    `CompareResultRecordBytesLoop`, `ReturnResultRecordByteCompare`,
    `DrawStoredResultRecords`, `DrawStoredResultRecordLoop`,
    `DrawStoredBTypeResultDetail`, `AdvanceStoredResultRecordRow`,
    `DrawResultRecordDigitRun`, `DrawResultRecordDigitRunLoop`,
    `AdvanceSuppressedResultRecordDigit`,
    `DrawResultRecordNonzeroDigit`, `AdvanceResultRecordDigitRun`,
    `FillResultRecordBoxRowMiddleLoop`, `FadeInResultRecordPalette`,
    `FadeInResultRecordPaletteLoop`, and `ResultRecordPaletteSequence`.
  - Replaced the misleading previous result-record comparison, rendering,
    input-wait, palette-fade, and palette-data names in source, symbols, and
    recovery docs.
  - Updated result-record, memory-map, data-range, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old names and old local labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - Bank 0/1 still have 647 generated local label definitions remaining.

### Phase 3/4: 1P Preplay Input Branch Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the 1P pre-play input branch labels by behavior:
    `Handle1PPreplayNonStartInput`, `Move1PPreplayCursorUp`,
    `Move1PPreplayCursorDown`, `Increment1PPreplaySelectedOption`, and
    `Decrement1PPreplaySelectedOption`.
  - Renamed the duplicate option-limit table used by this loop to
    `PreplayLoopOptionCountTable`.
  - Synced `Yoshi/yoshi.sym` with the already-recovered pre-play source labels:
    `InitPreplayBlinkTimer`, `Init1PPreplayScreen`,
    `Draw1PPreplayScreen`, and `Run1PPreplayLoop`.
  - Updated option-variable, state-machine, data-range, findings, task-plan,
    and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old local labels and stale symbol aliases no longer appear in
    source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - Bank 0/1 still have 642 generated local label definitions remaining.

### Phase 3/4: 1P Preplay Screen Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Replaced misleading win/lose-style labels in the 1P pre-play area with
    behavior names:
    `Draw1PPreplayBackground`, `Draw1PPreplayHeaderText`,
    `Draw1PPreplayGameTypeLabel`, `Draw1PPreplayLevelLabel`,
    `Draw1PPreplaySpeedLabel`, `Draw1PPreplayBgmLabel`,
    `Draw1PPreplayLevelText`, `Draw1PPreplaySpeedText`,
    `Draw1PPreplayGameTypeText`, `Draw1PPreplayBgmOffText`, and
    `Draw1PPreplayBgmMarker`.
  - Renamed the local text/tile selection branches for speed, level,
    game-type, and BGM marker drawing.
  - Synced result/text data notes, settings-blink notes, graphics-load notes,
    memory-map notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old names and local labels no longer appear in source, symbols, or
    recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - Bank 0/1 still have 621 generated local label definitions remaining.

### Phase 3/4: 2P Preplay Input Branch Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the 2P pre-play start-handshake and non-Start input branch labels
    by behavior: `Check2PPreplayReceivedStartHandshake`,
    `Poll2PPreplayNonMasterInput`, `Enter2PPreplayPlaySetup`,
    `Handle2PPreplayNonStartInput`, `Move2PPreplayCursorUp`,
    `Move2PPreplayCursorDown`, `Increment2PPreplaySelectedSetting`, and
    `Decrement2PPreplaySelectedSetting`.
  - Synced `Yoshi/yoshi.sym` with the recovered labels and the existing
    `LinkSettingsOptionCountTable` data label.
  - Updated link-state, state-machine, settings-blink, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old 2P pre-play local labels no longer appear in source, symbols,
    or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - Bank 0/1 still have 613 generated local label definitions remaining.

### Phase 3/4: 2P Preplay Screen Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Replaced the misleading score/stat-style labels in the 2P pre-play screen
    area with behavior names: `Init2PPreplayBlinkTimer`,
    `Draw2PPreplayScreen`, `Draw2PPreplayDynamicSettings`,
    `Draw2PPreplayBackground`, `Draw2PPreplayRoleHeader`,
    `Draw2PPreplaySpeedText`, `Draw2PPreplayRolePanels`,
    `Draw2PPreplayLevelLabel`, `Draw2PPreplaySpeedLabel`,
    `Draw2PPreplayLevelText`, and `Draw2PPreplayLevelTextAtIndex`.
  - Renamed the local role, speed, label-highlight, and level-text selection
    branches used by the same 2P setup screen.
  - Synced `Yoshi/yoshi.sym`, data-range notes, settings-blink notes,
    state-machine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old 2P pre-play screen labels and local labels no longer appear in
    source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 599 generated local label definitions remaining.

### Phase 3/4: 2P Link Packet Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the 2P link tick packet dispatch branches by behavior:
    `SendNextLinkQueueByte`, `AdvanceLinkSendQueueIndex`,
    `StoreNextLinkSendQueueIndex`, `DispatchReceivedLinkPacket`,
    `CheckReceivedLinkFieldCountPacket`,
    `CheckReceivedLinkFieldRisePacket`, and
    `HandleReceivedLinkPausePacket`.
  - Renamed the bit-6 and bit-7 packet handlers to
    `ProcessLinkFieldRisePacket` and `ProcessLinkResultPacket`.
  - Renamed the result-code exchange helper to `Exchange2PResultCode`, with
    local labels for waiting on the peer packet and returning from the exchange.
  - Synced `Yoshi/yoshi.sym`, link-state notes, memory-map notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old link packet and result-exchange labels no longer appear in
    source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 589 generated local label definitions remaining.

### Phase 3/4/5: Field Timer And Link Count Loop Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the field-column timer loop labels inside `UpdateFieldTimers`:
    `UpdateFieldColumnTimerLoop` and `AdvanceFieldColumnTimerSlot`.
  - Renamed the sprite object slot clear loop to `ClearSpriteObjectSlotLoop`.
  - Renamed the two-digit link field-count renderer loop labels:
    `CountLinkFieldTensDigitLoop` and `StoreTwoDigitLinkFieldCount`.
  - Renamed the 2P field occupancy sampler loops:
    `ScanLinkFieldOccupancyRow`, `ScanLinkFieldOccupancyColumn`, and
    `AdvanceLinkFieldOccupancyColumn`.
  - Synced `Yoshi/yoshi.sym`, field-animation notes, link-state notes,
    findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old anonymous loop labels no longer appear in source, symbols, or
    recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 581 generated local label definitions remaining.

### Phase 4: Sprite OAM Expansion Loop Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed Bank 1 `UpdateSprites` local labels for the logical sprite object
    scan and shadow OAM expansion path:
    `BeginSpriteOamExpansion`, `ScanSpriteObjectSlotLoop`,
    `LoadSpriteFramePointer`, `DrawSpriteObjectFrame`,
    `DrawSpriteObjectOamEntryLoop`, `StoreSpriteObjectOamAttributes`,
    `AdvanceSpriteObjectSlot`, and `HideUnusedShadowOamLoop`.
  - Renamed the `InitSpriteBuffer` slot-type clear loop to
    `ClearSpriteObjectSlotTypesLoop`.
  - Synced `Yoshi/yoshi.sym`, sprite/OAM notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old Bank 1 sprite/OAM anonymous labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 572 generated local label definitions remaining.

### Phase 4/5: Countdown Score And Playfield Loop Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the misleading `UpdateAnimFrame` entry to
    `Draw1PCountdownDigitTileSlots`, matching its 1P-only countdown tile slot
    draw and `COUNTDOWN_BLIT_TIMER` seed behavior.
  - Replaced the old countdown tail label with
    `DrawCountdownDigitTileSlotTail` and named the low-nibble tile digit loop
    `UnusedDrawLowNibbleTileDigitsLoop`.
  - Named local loops/branches in the Bank 1 score and playfield update area:
    `ClearScoreAccumulatorAndDigitsLoop`, `UseBlankUnusedBcdTensTile`,
    `StoreUnusedBcdDigitTiles`, `ContinueGameMainAfterTimerDraw`,
    `ReturnFromGameplayFrame`, `FillGameplayBgTopRowLoop`, and
    `CopyFieldColumnTilePatternLoop`.
  - Synced call sites in Bank 0/1 plus `Yoshi/yoshi.sym`, countdown-buffer
    notes, memory-map/data-range notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old countdown/score/playfield labels and anonymous local labels no
    longer appear in source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 557 generated local label definitions remaining.

### Phase 4/5: Next-Round And Tilemap Helper Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the local 1P/2P branch labels in `StartNextRound`:
    `SetupNextRoundSinglePlayerSettings`,
    `SkipNextRoundActiveLevelIncrement`, and `ContinueNextRoundSetup`.
  - Renamed the coordinate rectangle fill helper loops:
    `FillTilemapRectRowLoop`, `FillTilemapRectColumnLoop`, and
    `AdvanceTilemapRectRow`.
  - Renamed the sequential tile-row helper loop to
    `DrawSequentialTileRowLoop`.
  - Synced `Yoshi/yoshi.sym`, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old next-round/tilemap anonymous labels no longer appear in
    source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 550 generated local label definitions remaining.

### Phase 4/5: Level And Egg Display Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed Bank 1 level display rollover locals:
    `IncrementATypeLevelDisplayDigits`, `StoreATypeLevelDisplayOnes`,
    `IncrementLevelDisplayDigits`, and `StoreLevelDisplayOnes`.
  - Renamed `DrawEggTextFrameByIndex` local selection branches:
    `UseBTypeEggTextCoord`, `SelectEggTextFrame`, `UseEggTextFrame0`,
    `UseEggTextFrame1`, `UseEggTextFrame2`, `DrawEggTextFrameRows`, and
    `ReturnFromEggTextFrameDrawIn2P`.
  - Renamed egg count render/increment locals:
    `UseATypeEggCountCoord`, `DrawPlayfieldEggCountDigitsAtCoord`, and
    `RefreshEggCountDigitsAfterIncrement`.
  - Synced stale `Yoshi/yoshi.sym` entries so `01:$465D` and `01:$4681`
    match the recovered `DrawPlayfieldEggCountDigits` and `IncrementEggCountAndRefreshDisplay` source
    labels instead of older placeholder names.
  - Updated egg-counter notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old level/egg display anonymous labels and stale symbol aliases no
    longer appear in source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 536 generated local label definitions remaining.

### Phase 3/4: Title Marker And Title-Link Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Replaced the misleading title marker labels with behavior names:
    `DrawTitlePlayerSelectionMarker`, `DrawTitleTwoPlayerSelectionMarker`,
    `TickTitlePlayerMarkerBlink`, `DrawTitlePlayerMarkerTop`, and
    `DrawTitlePlayerMarkerBottom`.
  - Renamed title input branches to `SelectTitleTwoPlayerMode`,
    `SelectTitleOnePlayerMode`, and `ToggleTitlePlayerMode`.
  - Renamed title/link transition branches to `PollTitleStartOrReceivedLink`,
    `HandleTitleLinkHandshakeByte`, `CheckTitleLinkMasterHandshake`,
    `AcceptTitleLinkHandshake`, and `EnterPreplayInitFromTitle`.
  - Synced `Yoshi/yoshi.sym`, title-menu notes, option-variable notes,
    memory-map notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old title marker/link labels and anonymous labels no longer appear
    in source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 526 generated local label definitions remaining.

### Phase 2/4/5: Egg Text Pulse And BG Map Copy Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `UpdateEggTextAnimation` local pulse branches:
    `DrawEggTextPulseFrame2`, `ToggleEggTextPulseFrame`, and
    `ReturnAfterEggTextPulseComplete`.
  - Renamed `ProcessFieldLogic` BG map shadow slice-copy locals:
    `SelectBgMapShadowCopySlice0`, `SelectBgMapShadowCopySlice1`,
    `StoreNextBgMapShadowCopyPhase`, `CopyBgMapShadowSliceRowLoop`, and
    `CountBgMapShadowCopySliceRow`.
  - Synced `Yoshi/yoshi.sym`, egg-counter notes, VRAM-copy notes, findings,
    task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old egg-text/BG-copy anonymous labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 518 generated local label definitions remaining.

### Phase 2/4: VBlank And VRAM Copy Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the queued VRAM copy inner loop to
    `CopyQueuedVram16ByteBlockLoop`.
  - Renamed VBlank runtime branches:
    `CheckVBlankBusyCounter`, `ContinueVBlankRuntimeUpdates`,
    `ContinueVBlankAfterWaveUpdate`, and `ReturnFromVBlankHandler`.
  - Renamed the VBlank wait loop to `WaitVBlankSyncLoop` and the nearby
    joypad wait fragment loop to `WaitJoypadStartOrSelectPressLoop`.
  - Synced `Yoshi/yoshi.sym`, VRAM-copy notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old VBlank/VRAM anonymous labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 511 generated local label definitions remaining.

### Phase 4/5: Playfield HUD Coordinate Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the mode-selection locals inside `UpdateNextDisplay`,
    `ClearSpriteObjectBuffer`, `Draw1PPlayfieldSidePanelLabelRow0`,
    `DrawPlayfieldSidePanelLabelRow1`, `DrawPlayfieldLevelDigits`,
    `DrawPlayfieldSpeedValue`, `DrawPlayfieldEggDisplay`, and
    `DrawTwoPlayerPlayfieldRoleHeaders`.
  - Added packed coordinate constants for the 2P, A-type, and B-type
    playfield level/speed/egg display positions.
  - Replaced raw speed-value width/tile-base literals with
    `PLAYFIELD_SPEED_VALUE_WIDTH` and `PLAYFIELD_SPEED_VALUE_TILE_BASE`.
  - Labeled the currently unreferenced header fragment between
    `DrawPlayfieldRoundTimerDigits` and `DrawTwoPlayerPlayfieldRoleHeaders`
    as `UnusedDrawPlayfieldGameTypeHeader`.
  - Updated egg-counter notes, findings, task-plan, checklist, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old playfield HUD local labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 492 generated local label definitions remaining.

### Phase 2/4: VBlank Sound And Timer Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the stale wave-update entry to `HandleWaveUpdate`; the normal
    selected 16-byte wave-pattern copy is in `ProcessNote`, while this VBlank
    path handles the `WAVE_UPDATE` flag.
  - Renamed stale timer symbol entries to the
    source labels `UpdateElapsedTimers` / `TickElapsedTimerDigits`.
  - Renamed the stale link-style sound update labels to
    `UpdateSoundChannels` / `TickSoundChannel` because the routines scan and
    tick the eight sound-channel work arrays.
  - Named local branches for the elapsed-timer clamp path and the sound-channel
    pause, modulation, delay, pitch-slide, and vibrato paths.
  - Added `SOUND_CHANNEL_COUNT`, `SOUND_LAST_CHANNEL_INDEX`,
    `SOUND_PRIMARY_CHANNEL_COUNT`, and `WAVE_UPDATE_BITS_PER_SOURCE_BYTE`.
  - Updated `Yoshi/yoshi.sym`, sound-engine notes, findings, task-plan,
    checklist, and estimate notes.
- Test result:
  - First verification failed because one renamed vibrato branch bypassed the
    original intermediate `jr`, changing one byte at ROM offset `$4D35`.
  - Restored the intermediate branch as
    `UseSoundVibratoSubtractedFrequency`, then `tools/verify_yoshi_build.sh`
    passed and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted stale wave/timer/sound labels and anonymous local labels no
    longer appear in source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 472 generated local label definitions remaining.

### Phase 4: Sound Sequence Parser Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `$FF` sequence-end local branches to
    `ReturnFromSoundSubsequence`, `EndSoundSequenceChannel3Plus`,
    `DisableSoundChannelOutputOnEnd`, `ClearSoundChannelAfterEnd`, and
    `ClearSoundChannelActiveId`.
  - Renamed the `$FE` loop/jump locals to `IncrementSoundLoopCounter` and
    `JumpSoundSequenceToLoopTarget`.
  - Renamed the `$D0-$DF` length/envelope locals to
    `UseMainWavePatternSelector`, `StoreWavePatternSelectorAndEnvelope`,
    `StoreSoundEnvelope`, and `ContinueSoundCommandParsing`.
  - Renamed the `$E8/$EA/$EB` extended command checks to
    `CheckSoundVibratoCommand` and `CheckSoundPitchSlideCommand`.
  - Renamed the `$EC/$ED/$EE/$EF/$FC/$F0` extended command checks to
    `CheckSoundDutyLengthCommand`, `CheckSoundTempoCommand`,
    `CheckSoundOutputMaskCommand`, `CheckNestedSoundCommand`,
    `CheckSoundDutyRotateCommand`, and `CheckSoundMasterVolumeCommand`.
  - Synced the old intro-animation-style symbol to
    `CheckSoundMasterVolumeCommand`.
  - Renamed the `$F1/$F8/$E0` command checks to
    `CheckSoundVisualUpdateCommand`, `CheckSoundGateFlagCommand`, and
    `CheckSoundOctaveCommand`.
  - Renamed the first note/sweep/channel-3 nested-sound branch points to
    `CheckSoundExtendedNoteCommand`, `CheckSoundSweepCommand`,
    `CheckChannel3NestedSoundCommand`,
    `ReadChannel3NestedSoundOperand`,
    `TriggerChannel3NestedSoundIfAllowed`, and
    `ContinueAfterChannel3NestedSound`.
  - Updated sound-engine notes, findings, task-plan, checklist, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both ROMs remains
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Targeted old sound parser local labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 still have 436 generated local label definitions remaining.

### Phase 4: Sound Note And Output Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the old note handler to `ProcessSoundNoteCommand`.
  - Renamed nearby note-length, tempo-selection, rest, pitch-note,
    output-mask, and length-register local branches by observed side effects.
  - Synced `Yoshi/yoshi.sym` and sound-engine notes with the recovered names.
  - Corrected two stale call/jump references and restored the original branch
    target for the `rNR51` write path after verification exposed the mismatch.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound note/output cleanup.
  - `Yoshi/yoshi.gb` and `Yoshi/game.gb` both have SHA-256
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 now have 421 generated local label definitions remaining.

### Phase 4: ProcessNote And Sound Index Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `ProcessNote` locals for selected wave-pattern lookup/copy and
    final frequency-trigger register writes.
  - Renamed the adjacent sound sequence pointer rewind result labels and
    pitch-slide frequency store path.
  - Renamed `InitSoundPitchSlideForNote` locals for tick-count clamping,
    ascending setup, slide-step calculation, and step storage.
  - Renamed `SoundUpdate3/4/5` utility locals for register-offset lookup,
    multiply looping, and pitch-table shifting.
  - Renamed `SoundEngine` / `SoundLookupIndex` locals for BGM-range reset,
    sound-entry priority checks, per-channel state clear, channel expansion
    continuation, and the generic sound-state fill loop.
  - Updated sound-engine notes, findings, task-plan, checklist, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after these local-label cleanups.
  - Targeted old anonymous sound local labels no longer appear in source,
    symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 now have 396 generated local label definitions remaining.

### Phase 4: StartSoundSequence And Sound Boundary Sync
- **Status:** completed
- Actions taken:
  - Renamed `StartSoundSequence` locals for sequence-pointer slot search,
    channel entry installation, BGM active-state setup, and return path.
  - Synced `Yoshi/yoshi.sym` with the recovered Bank 1 sound boundaries:
    `$55E2-$5668` code, `$5669-$5699` support tables, `$569A-$7C01`
    sequence data, `$7C02-$7C2B` code, and `$7C2C-$7FFF`
    sound index/wave/tail data.
  - Updated stale sound data-range notes to use
    `UpdateSoundChannelOutputMask`.
  - Updated sound-engine notes, findings, task-plan, checklist, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the StartSoundSequence cleanup
    and symbol-boundary sync.
  - Targeted old StartSoundSequence local labels and stale sound boundary
    directives no longer appear in source, symbols, or recovery docs.
  - Raw `$Cxxx` references in `bank_000.asm` / `bank_001.asm` remain 0.
  - Raw direct branch scan still has no `call $`, `jp $`, or `jr $` matches.
  - `git diff --check` reports no whitespace errors.
  - Bank 0/1 now have 389 generated local label definitions remaining.

### Phase 3/4: Bank 0 Initial Utility Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the joypad release polling loop to
    `WaitJoypadLinesReleasedLoop`.
  - Renamed the LCD disable scanline wait loop to
    `WaitForLCDOffSafeLine`.
  - Renamed the shadow OAM clear and hide loops to `ClearShadowOamLoop`
    and `HideShadowOamSpritesLoop`.
  - Renamed the small byte-duplication loop after `MemcopyCall` to
    `CopyBytesDuplicatedLoop`, limiting the name to its observed behavior.
  - Updated memory-map, sprite/OAM, work-estimate, findings, and task-plan
    notes for the recovered utility labels.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the five old `jr_000_*` labels returned no
    matches in source/docs.
  - Generated local label count is 384.

### Phase 2/3: Bank 0 Startup Clear Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the invalid-magic branch to `UseFullWRAMClear`.
  - Renamed the WRAM clear setup and loop labels to `BeginWRAMClear`,
    `ClearWRAMLoop`, and `ClearWRAMByte`.
  - Renamed the startup VRAM and HRAM clear loops to `ClearVRAMLoop` and
    `ClearHRAMWorkAreaLoop`.
  - Updated memory-map, result-record, work-estimate, findings, and task-plan
    notes to document the result-record preserve path and startup clear loops.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the six old startup clear `jr_000_*` labels
    returned no matches in source/docs.
  - Generated local label count is 378.

### Phase 2/4: Bank 0 Tilemap Fill Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the shared BG-map shadow fill setup and loop to
    `BeginBgMapShadowFill` and `FillBgMapShadowLoop`.
  - Renamed the hardware tilemap fill setup and loop to
    `BeginHardwareTilemapFill` and `FillHardwareTilemapLoop`.
  - Updated memory-map, VRAM-copy, work-estimate, findings, and task-plan notes
    for the recovered fill paths.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the four old tilemap fill `jr_000_*` labels
    returned no matches in source/docs.
  - Generated local label count is 374.

### Phase 2/4: Bank 0 Tilemap Address Carry Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `CalcTilemapAddress` carry-continuation labels to
    `AddTilemapColumnOffset`, `AddBgMapShadowBaseLow`, and
    `StoreCalculatedTilemapAddressLow`.
  - Updated memory-map, work-estimate, findings, and task-plan notes for the
    recovered `BG_MAP_SHADOW + row * BG_MAP_ROW_STRIDE + column` calculation.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the three old `CalcTilemapAddress`
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 371.

### Phase 3/4: Bank 0 MainLoop And Pause Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the MainLoop state chain labels to
    `DispatchTitleMenuState`, `DispatchPlaySetupState`,
    `DispatchPlayingState`, `DispatchRoundEndState`,
    `DispatchPreplayLoopState`, and `DispatchPreplayInitState`.
  - Renamed play setup and state-store tails to
    `PlaySinglePlayerSelectedBgm`, `InitPlayfieldAfterBgmSetup`,
    `IgnoreInvalidGameStateAndLoop`, and `StoreGameStateAndLoop`.
  - Renamed the game-tile load bank-restore tail to
    `RestoreMainBankAfterGameTileLoad`.
  - Renamed pause locals to `CheckPauseButtonInput`,
    `WaitPauseResumeInputLoop`, `PlayPauseSoundAndHalt`, and
    `WaitLinkPeerUnpauseLoop`.
  - Updated state-machine, memory-map, work-estimate, findings, and task-plan
    notes for the recovered labels.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old state/load/pause `jr_000_*` labels
    returned no matches in source/docs.
  - Generated local label count is 356.

### Phase 4/5: Bank 0 Sprite Object Wait And Masked Count Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `MultiplyAndCount` locals to `CountMaskedMultiplyBitsLoop` and
    `ContinueMaskedMultiplyBitCount`, matching the masked random set-bit count
    used by piece display shuffles.
  - Renamed `UpdateSpriteObject` locals to `TickSpriteObjectWaitPhase` and
    `WriteBackSpriteObjectStaging`.
  - Updated piece-display, sprite/OAM, work-estimate, findings, and task-plan
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old masked count and sprite-object
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 352.

### Phase 4/5: Bank 0 Tile Sprite And Board Draw Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `CopyEncodedTilePatternRow4SkipFF` skip/advance labels to
    `AdvanceAfterConditionalSpriteByte0..2` and
    `ReturnAfterConditionalSpriteBytes`.
  - Renamed `DrawGridPiece` locals to `DrawGridPieceWithinBounds` and
    `DrawGridPieceSecondRow`.
  - Renamed column clear loops to `ClearColumnLeftLoop`,
    `ReturnFromClearColumnLeft`, `ClearColumnRightLoop`, and
    `ReturnFromClearColumnRight`.
  - Renamed `DrawAllColumns` loops to `DrawAllColumnsColumnLoop`,
    `DrawAllColumnsRowLoop`, and `AdvanceDrawAllColumnsColumn`.
  - Updated board-layout, sprite/OAM, work-estimate, findings, and task-plan
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old tile-sprite and board-draw
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 339.

### Phase 4/5: Bank 0 Column Blink Sprite Draw Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `DrawColumnSprite` local labels for top-row lookup and three
    conditional tile-row writes: `ReadColumnTopRowForSprite` and
    `DrawColumnSpriteRow0..2`.
  - Renamed the narrow alternate row fragment to
    `UnreachedColumnSpriteAlternateRowFragment`,
    `UnreachedColumnSpriteWrapRow`, and
    `UnreachedColumnSpriteContinueAtRow1`, because an unconditional branch
    skips this fragment on the live path.
  - Updated column-state, column-blink, work-estimate, findings, and task-plan
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old `DrawColumnSprite` `jr_000_*`
    labels returned no matches in source/docs.
  - Generated local label count is 333.

### Phase 5: Bank 0 Drop Animation Completion Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the remaining `AnimateDropping` cascade setup/end labels:
    `BeginDropDownCascade`, `CheckDropDownCascadeEnd`,
    `BeginDropUpCascade`, and `CheckDropUpCascadeEnd`.
  - Renamed the drop completion and column-swap path to
    `FinishDropCascadeAndSwapColumns`, `BeginDropAnimationColumnSwap`,
    `SwapDropAnimationColumnCellsLoop`, and `SwapColumnTopRowsAfterDrop`.
  - Updated drop-animation, column-state, work-estimate, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old drop completion `jr_000_*` labels
    returned no matches in source/docs.
  - Generated local label count is 325.

### Phase 5: Bank 0 Drop Collision And Position Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `CheckCollisionCore` scan locals to
    `ScanDropCollisionSpriteSlotsLoop`, `SkipInactiveDropCollisionSlot`,
    `AdvanceDropCollisionSlot`, and `ReturnDropCollisionDetected`.
  - Renamed `UpdateDropPositions` locals to `UpdateDropPositionsLoop` and
    `AdvanceDropPositionSlot`.
  - Updated drop-animation, sprite/OAM, work-estimate, findings, and task-plan
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old drop collision/update `jr_000_*`
    labels returned no matches in source/docs.
  - Generated local label count is 319.

### Phase 5: Bank 0 Drop State, Board Pattern, And Column Blink Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the remaining `AnimateDropDown` and `AnimateDropUp` state branch
    labels by behavior, including the state-2/state-3 checks, final handlers,
    redraw branches, and boundary branches.
  - Renamed `ClearAnimStateLoop` and `ReturnFromStartDropAnim`.
  - Labeled the unreferenced coherent board-fill fragment at `00:$09C8` as
    `UnusedFillBoardDataPattern`, with local labels for the column loop,
    leading-byte clear loop, index-byte fill loop, and tail-byte store.
  - Renamed `UpdateColumnBlinkState` local branches to
    `BeginColumnBlinkSlotScan`, `ColumnBlinkSlotLoop`,
    `TickColumnBlinkSlotTimer`, `ToggleColumnBlinkSlotFrame`,
    `SetColumnBlinkFrame1`, `DrawColumnBlinkSlot`, and
    `AdvanceColumnBlinkSlot`.
  - Synced `Yoshi/yoshi.sym` with `UnusedFillBoardDataPattern` and
    `UpdateColumnBlinkState`.
  - Updated drop-animation, board-layout, column-blink, work-estimate,
    findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old drop-state, unused board-pattern,
    and column-blink `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 287.

### Phase 3/5: Bank 0 Multiply Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `Multiply` internal branch labels to
    `MultiplyShiftMultiplierLoop`, `AddShiftedMultiplicandToProduct`, and
    `ShiftMultiplicandForNextBit`.
  - Left the names local to the arithmetic behavior rather than asserting a
    broader random-number or gameplay role.
  - Updated findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old `Multiply` `jr_000_*` labels
    returned no matches in source/docs.
  - Generated local label count is 284.

### Phase 3/5: Bank 0 Game-State Init And Drop Cursor Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `InitGameState` local branches to
    `InitSinglePlayerLevelSpeedSettings` and
    `InitTwoPlayerLevelSpeedSettings`.
  - Added `DROP_CURSOR_FRAME_ALT_START` and `DROP_CURSOR_FRAME_WRAP` for the
    slot-0 drop cursor frame boundaries.
  - Renamed `InitGameState2` local branches to `AdvanceDropCursorAltFrame`,
    `StoreAdvancedDropCursorFrame`, and `StopDropCursorFrameAnimation`.
  - Updated column-state, state-machine, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old game-state init/drop-cursor
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 279.

### Phase 4/5: ProcessMatching Animation Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `ProcessMatching` local branches for state clamp/store,
    middle-OAM tile ID setup, intro scroll/blink, result-panel scroll/blink,
    top-OAM right slide, combined OAM left slide, result-panel right-edge fill,
    final-OAM tile ID setup, and final upward OAM movement.
  - Updated sprite/OAM, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old `ProcessMatching` `jr_000_*` labels
    returned no matches in source/docs.
  - Generated local label count is 264.

### Phase 4/5: Matching Score Result Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `UpdateScore` sound-completion wait loop to
    `WaitMatchingScoreSoundEndLoop`.
  - Renamed the `UpdateLevel` five-digit score tile loop to
    `DrawResultScoreDigitsLoop`.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old matching score/result `jr_000_*`
    labels returned no matches in source/docs.
  - Generated local label count is 262.

### Phase 4/5: FillRect And Gameplay Display Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `FillRect` row/column loops to `FillRectRowLoop` and
    `FillRectColumnLoop`.
  - Renamed the `UpdateGameplayObjectSlotsAndRoundState` gameplay-object update
    loop, B-type column-clear scan, active-object return path,
    `UpdatePieceFallTimer` fall-timer reload,
    `UpdatePieceDisplayByGameType` B-type display branch,
    `CheckGameplayObjectSlotsActive` active-slot scan, and
    `UpdateFallAcceleration` fall-acceleration reload branches by behavior.
  - Updated sprite/OAM, fall-timing, piece-display, memory-map, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old FillRect/gameplay display
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 248.

### Phase 5: HandlePlayfieldInput Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `HandlePlayfieldInput` local branches for cursor-move sound
    gating, A/B drop-start acceptance, left/right cursor movement, Down-held
    active-slot checks, and fast-fall timer clamp loops.
  - Updated fall-timing, sprite/OAM, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old `HandlePlayfieldInput` `jr_000_*`
    labels returned no matches in source/docs.
  - Generated local label count is 239.

### Phase 5: UpdateMatchState Fall Landing Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the `UpdateMatchState` local branches for fall-position advance,
    reached-column handling, landed-piece redraw/top-row update, single-player
    overflow result entry, and selected gameplay object clearing.
  - Renamed selected-column carry tails, the clear loop for piece sprite slots,
    the generic array read carry tail, and the B-type fall-timing init branch
    tails by behavior.
  - Updated board-layout, fall-timing, sprite/OAM, memory-map, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old `UpdateMatchState` fall/landing
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 224.

### Phase 5: Board Piece Setup Local Loop Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the local loops for board clearing, column-top seeding, piece-code
    pool initialization, initial B-type board fill, and VBlank wait.
  - Renamed the initial-board adjacent-duplicate return/trampoline labels, the A/B-type playfield
    setup tails, the slot-0 type write tail, and the capped level-fall-delay
    table read tail.
  - Updated board-layout, fall-timing, piece-display, sprite/OAM, memory-map,
    findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old board/piece setup `jr_000_*`
    labels returned no matches in source/docs.
  - Generated local label count is 213.

### Phase 5: Board Scan Animation Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `ScanBoard` local branches for scan-distance parameter storage,
    board-scan animation stepping, trigger-payload drawing, and scan-step
    send-frame waits.
  - Renamed `FindBoardScanTargetRow` return paths and
    `ReadBoardCellAtColumnRow` computed-address carry tails by behavior.
  - Updated board-layout, fall-timing, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old board scan animation/cell-read
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 203.

### Phase 4/5: Round Complete Send Display Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the round-complete tile-slot initialization loop, transition-frame
    send loop, reward sound/reward tail, and `Send2PData` early abort path.
  - Renamed `DisplayResults` local branches for setting up, clearing, and
    rebuilding the piece display state array.
  - Updated piece-display, sprite/OAM, link-state, memory-map, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old round-complete/send/display
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 195.

### Phase 4/5: Piece Display Menu Selection Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `ApplyFirstForcedPieceDisplayState`,
    `ApplyAllForcedPieceDisplayStates`, the piece-display object builders,
    `ProcessMenuInput`, `ProcessMenuLoop`,
    `UpdateMenuCursor`, `DrawMenuCursor`, and `ProcessMenuSelection` local
    branches by behavior.
  - Named the B-type timer-gated special-selection path, default random
    selection path, return-code labels, field-occupancy scan loops, active
    display-object count loop, and all-state forced-display loop.
  - Updated piece-display, sprite/OAM, memory-map, link-state, fall-timing,
    findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old piece-display/menu-selection
    `jr_000_*` labels returned no matches in source/docs.
  - Generated local label count is 167.

### Phase 3/4/5: Link Field Rise Blink And Option UI Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `SelectMenuItem` local branches for two-player state selection and
    pending link field-rise consumption.
  - Renamed `UpdatePieceDisplayBlink` and `TogglePieceDisplayFrame` local
    branches for slot scanning, slot advance, and frame-toggle return.
  - Renamed option/BG helper loops for option decoration tiles, box side rows,
    and generic tile-run filling.
  - Updated link-state, piece-display, memory-map, options, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old link/blink/option UI `jr_000_*`
    labels returned no matches in source/docs.
  - Generated local label count is 157.

### Phase 3/4: Option Marker And Detached Preplay Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `DrawOptionMarkers` local branches for marker clear, selected
    A/B game marker, selected speed marker, and BGM option marker selection.
  - Renamed the detached pre-play-like input fragment immediately after
    `RunPreplayLoop` with `DetachedPreplay*` labels so it is not confused with
    the live `Run1PPreplayLoop` / `Run2PPreplayLoop` paths.
  - Renamed `ApplyGameSettings` local branches for link-role sounds,
    single-player BGM preview selection, and BGM-off handling.
  - Renamed option cursor/value drawing labels:
    `DrawLevelCursorHighlight`, `DrawSpeedCursorHighlight`,
    `DrawBgmCursorHighlight`, `DrawOptionLevel0Value` through
    `DrawOptionLevel4Value`, `DrawBGameOptionLabel`, and
    `ReturnFromDrawOptionGameTypeLabel`.
  - Synced `Yoshi/yoshi.sym` with the recovered option UI labels, replacing
    old misleading labels such as `UpdateHighScore`, `LoadSettings`,
    `SaveSettings`, `OptionsScreen`, `SaveConfig1..3`, and `DrawOptionItem`.
  - Updated option data/routine notes, findings, task plan, and work estimate.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old option/preplay source and symbol
    labels returned no matches in `Yoshi/bank_000.asm` or `Yoshi/yoshi.sym`.
  - `git diff --check` passed.
  - Generated local label count is 124.

### Phase 3/4/5: Serial String Preplay Init And Field Animation Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `SerialHandler` local branches for the unassigned-role path,
    unassigned serial-byte clear, and common interrupt completion.
  - Renamed `DrawStringToGrid` local branches for the `$FF`-terminated copy
    loop and row advance.
  - Renamed `StartGameplay` 2P pre-play init branches for the link-role sound
    choice and shared 2P setup tail.
  - Renamed field-animation sentinel cleanup tails:
    `EndFieldAnimSlot10`, `EndFieldAnimSlot11`, `EndFieldAnimSlot12`, and
    `EndFieldAnimSlot13`.
  - Updated link-state, title-menu, state-machine, field-animation, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old serial/string/preplay/field-animation
    local labels returned no matches in source/docs.
  - `git diff --check` passed.
  - Generated local label count is 112.

### Phase 3/4/7: Link Settings Exchange And Result Record Init Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `UpdateGameField` local branches for the 2P pre-play settings
    exchange start and serial-completion wait.
  - Renamed `RefreshField` one-time result-record head initialization labels:
    `InitATypeResultRecord0`, `InitATypeResultRecord1`,
    `InitATypeResultRecord2`, and `InitBTypeResultRecords`.
  - Updated link-state, result-record, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old link-settings/result-init local
    labels returned no matches in source/docs.
  - `git diff --check` passed.
  - Generated local label count is 106.

### Phase 4: Countdown Digit Buffer Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `DrawCountdownNum` loop for clearing countdown sprite frame high
    bits.
  - Renamed `UpdateCountdownTimer` local branches for phase-0 and phase-1
    countdown digit buffer construction.
  - Renamed `RandomNext` local loops for phase-0 and phase-1 doubled-byte VRAM
    staging.
  - Updated countdown digit buffer, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old countdown local labels returned no
    matches in source/docs.
  - `git diff --check` passed.
  - Generated local label count is 86.

### Phase 3/4/5: Round-End And Link Result Local Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `ProcessRoundComplete` single-player tile-slot initialization as
    `InitRoundCompleteTileSlotsFromBaseLoop`.
  - Renamed `HandleRoundEnd`, `DrawScoreRanking`, `ProcessRoundResultAndEnterRoundEnd`,
    `DrawRankEntry`, `CalcRankPosition`, `UpdateLinkResultMarksAndScreen`, and
    `WaitLinkStartConfirm` local branches by observed behavior.
  - Patched two `WaitTerminalLinkResultMenuConfirm` branches to use the shared
    `ReturnLinkConfirmWithCarry` tail.
  - Moved `HandleSinglePlayerRoundCompleteFlow` back before the `GAME_TYPE`
    load after the first verifier run caught the shifted branch target.
  - Updated sprite/OAM, result-rank, link-state, result-record, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the branch-target label fix.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Targeted stale-label scan for the old round-end/rank/high-score/link-result
    local labels returned no matches in source/docs.
  - `git diff --check` passed.
  - Generated local label count is 36.

### Phase 3/4/5: Final Bank 0/1 Generated Local Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the detached pre-play label tile branch after `BgmMarkerNoneText`
    to `UseSelectedDetachedPreplayLabelTiles` /
    `DrawDetachedPreplayLabelTiles`.
  - Renamed the remaining result-confirm/menu/link-status branches around
    `WaitTerminalLinkResultMenuConfirm`,
    `DrawLinkResultConfirmPanelsAndWait`,
    `WaitLinkResultConfirmAndReloadTiles`, and
    `DrawLinkResultRoleStatusStrip`.
  - Renamed the remaining A-type round-complete summary and reveal branches:
    summary index selection, BG-map fill loops, message selection, reveal input
    polling, threshold checks, fixed-delay waits, and manual-OAM bonus movement.
  - Updated link-state, sprite/OAM, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated local label scan for `^jr_[0-9a-fA-F]{3}_[0-9a-fA-F]{4}:`
    returned no matches in Bank 0/1 source.
  - Targeted stale-label scan for the final old generated local labels returned
    no matches in source/docs.
  - `git diff --check` passed.

### Phase 4/5: BGM Preview And Fall Acceleration Leftover Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the former BGM preview period candidate to
    `BGM_PREVIEW_UNUSED_PERIOD` because the source writes BGM-specific values
    there but no direct read exists.
  - Renamed the former fall-acceleration level-3 leftover branch to
    `UnreachableReloadFallAccelTimerForLevel3`; `UpdateFallAcceleration`'s preceding
    `< 4` branch already catches level 3, so the later `cp $03` branch cannot
    be taken.
  - Renamed the orphaned number-pair helper to
    `UnusedDrawVerticalTilePairUnlessFF` to reflect its actual two-tile
    vertical draw behavior.
  - Updated options, memory-map, confidence/open-questions, fall-timing,
    data-range, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `git diff --check` passed.
  - Targeted stale-label scan for the old BGM/fall/orphan-helper names returned
    no matches in source/docs.

### Phase 2/4/5: Clear-Only And Write-Only WRAM Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `EGG_COUNT_UNUSED_BYTE` at `$C6D2` to reflect that current evidence
    only shows it being cleared with the egg counter.
  - Renamed `LINK_UNUSED_STAGING_BYTE` at `$C6FB` to reflect that
    `ClearLinkRoundState` clears it and no direct read exists in the current
    source.
  - Renamed `DROP_ANIM_UNUSED_GRID_ROW_TMP` at `$C762` to reflect that
    `CalcGridPosition` writes `b * 2` there but uses the value directly from
    register `H` rather than reading the WRAM byte back.
  - Updated memory-map, confidence/open-questions, egg-counter, link-state,
    drop-animation, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `git diff --check` passed.
  - Targeted stale-name scan for the previous egg/link/drop scratch names
    returned no matches in source/docs.

## Session: 2026-05-28

### Planning Checkpoint: Work Inventory And Estimate
- **Status:** completed
- Actions taken:
  - Recorded completed work, remaining work, and estimate rationale in
    `docs/source_recovery/work_plan_and_estimate.md`.
  - Added the latest completed chunks to `task_plan.md`:
    `PROGRESSION_LEVEL`, `BG_MAP_SHADOW`, and result record state.
  - Recorded current measured scale:
    145 raw `$Cxxx` occurrences and 87 distinct raw `$Cxxx` addresses remain
    in `Yoshi/bank_000.asm` / `Yoshi/bank_001.asm`.
  - Recorded the current estimate:
    20-40 hours for remaining high-confidence cleanup, 100-200 hours for a
    practical maintainable recovery, and no finite bound for original-source
    equivalence without the lost source.
- Files created/modified:
  - `docs/source_recovery/work_plan_and_estimate.md`
  - `task_plan.md`
  - `progress.md`

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
  - Corrected the `SoundPitchBaseTable` boundary: `$569A` is now the top-level
    title-BGM channel 0 sequence target, currently named
    `TitleBgmChannel0Sequence`.
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
  - Converted Bank 1 tail data `01:$7C2C-$7FFF` into `SoundIndexTable`, short `SoundSequenceData_*` entries, `SoundWavePatternPointerTable`, and `SoundWavePatternData_*`.
  - Removed fake `Call_001_7f9d` and `jr_001_7*` labels by representing the tail as data.
  - Verified the Bank 1 tail table/data recovery remains byte-identical to the preserved ROM.
  - Added `SOUND_*` WRAM constants for the sound engine work area `$C000-$C0ED`, replacing raw sound-state addresses in Bank 1 sound code and related Bank 0 pause/wait checks.
  - Updated sound-engine documentation to distinguish high-confidence pointer/active-ID/pause/output-mask fields from medium-confidence slide/tempo/envelope fields.
  - Added high-confidence sound ID constants and `SoundIndexTable` alias labels for drop start, falling-piece commit, piece landing, cursor movement, round complete, pause, title BGM, BGM option/preview choices, 2P link BGM choices, confirm, and stop/off.
  - Converted Bank 0 `00:$15FE-$1611` from fake instructions to `LevelFallDelayTable` and restored the real `00:$1612` landing-progress code entry.
  - Converted Bank 0 `00:$18CB-$18E3` from fake instructions to `RoundCompleteStateRemapTable` and `RoundCompleteDelayParamTable`.
  - Named Bank 1 `01:$432F` as `AddScore` and added score accumulator/display constants for `$C61D-$C621`.
  - Replaced Bank 0 direct calls to `$432F`, `$42F5`, `$43F2`, `$445C`, and `$4681` with `AddScore`, `Draw1PCountdownDigitTileSlots`, `DrawGameplayBgTopRowIfNoResultFlow`, `StartNextRound`, and `IncrementEggCountAndRefreshDisplay` where the target meaning is now known.
  - Converted Bank 1 `01:$442C-$445B` from fake instructions to `FieldColumnTilePatternTable` and preserved `StartNextRound` as the real code entry at `01:$445C`.
  - Named Bank 1 `01:$4681` as `IncrementEggCountAndRefreshDisplay`.
  - Converted Bank 0 `00:$22CC-$234B` from fake instructions to `FieldSideDeltaTable` and `FieldRowDeltaTable`, restoring `UpdateFieldTimers` as real code at `00:$234C`.
  - Replaced remaining high-confidence raw cross-bank direct calls with labels, including `WaitVBlank`, `VBlankHandler`, `InitSpriteBuffer`, `InitGameScreen`, `InitPlayfield`, `RunGameplayFrame`, `SoundEngine`, `DrawFieldColumnTilePattern`, `UpdateFieldTimers`, `DrawLevelDisplayDigits`, `DrawTitleLabels`, `ProcessTitleInput`, `ProcessOptionInput`, `FillTilemapRectByCoord`, and `DrawSequentialTileRowByCoord`.
  - Added `OAM_DMA_HRAM` for the HRAM DMA routine at `$FF80`, and replaced the VBlank call and setup copy target with that name.
  - Named Bank 1 `01:$4570` as `AdvanceATypeLevelDisplayDigits`.
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
  - Converted Bank 1 `DrawEggTextFrameByIndex` and `DrawTitleLabels` inline tile strings from bogus instructions to `db` rows.
  - Named the title 1P/2P selection marker blink timer/phase at `$C6BC/$C6BE`.
  - Named field animation cursors, active flags, and column timers at `$C6C3-$C6CE`, tying them to logical sprite object slots 10-13 and the `FieldSideDeltaTable` / `FieldRowDeltaTable` consumers.
  - Created `docs/source_recovery/field_animation_state.md` to document the recovered slot/timer mapping.
  - Named the title level-display tick divider at `$C6D1` and the egg counter digits at `$C6D3-$C6D5`; documented `$C6D2` as a cleared-with-counter reserved byte with no confirmed direct read.
  - Created `docs/source_recovery/egg_counter.md` to document the recovered egg counter and result-copy behavior.
  - Named the 2P selected level/speed bytes at `$C6EB-$C6EC`, peer received level/speed at `$C6FF-$C700`, and the two-byte link send queue at `$C6FC-$C6FE`.
  - Created `docs/source_recovery/link_state.md` to document the recovered 2P option packing, link send queue, and incoming bit-6 field-event accumulator.
  - Named the countdown digit staging buffers at `$C7AE-$C7CD` and the blit timer/phase bytes at `$C7CE-$C7CF`.
  - Created `docs/source_recovery/countdown_digit_buffers.md` to document how the score BCD digits expand into staging buffers and then blit to VRAM.
  - Named the column blink timers/flags at `$C7A4-$C7AC` and result rank position at `$C7AD`.
  - Created `docs/source_recovery/column_blink_state.md` to document the recovered blink slot arrays and result rank state.
  - Named the 2P pre-play settings cursor at `$C6F0` and the shared settings/result blink phase/timer at `$C6F1-$C6F2`.
  - Renamed the shared blink tick routine to `TickSettingsBlink` and created `docs/source_recovery/settings_blink_state.md`.
  - Replaced raw HRAM operands in `VRAMCopySetup` with the primary `VRAM_*` constants.
  - Confirmed `$FFB3-$FFB7` is not consumed by `VRAMCopyDMA` and named it as an unused secondary VRAM-copy slot.
  - Created `docs/source_recovery/vram_copy.md` to document the primary queue and the unreachable secondary-copy fragment.
  - Renamed the state `$05` pre-play dispatch and loop labels: `RunPreplayLoop`, `Run1PPreplayLoop`, `Run2PPreplayLoop`, `InitPreplayBlinkTimer`, `Init1PPreplayScreen`, and `Draw1PPreplayScreen`.
  - Updated `docs/source_recovery/state_machine.md` to record the 2P `$55` link-start handshake transition into `GAME_STATE_PLAY_SETUP`.
  - Renamed the state `$01` title frame loop from `InitGameVars` to `RunTitleMenu`.
  - Created `docs/source_recovery/title_menu.md` to document the title 1P/2P selection and Start/link entry path.
  - Converted `00:$254E-$254F` from apparent instructions to `LinkSettingsOptionCountTable`.
  - Converted `00:$2B9D-$2BA0` from apparent instructions to
    `ResultRecordPaletteSequence`.
  - Converted the fake-code head of the Bank 0 game-turn parameter table at `00:$0B8D-$0C3F` to explicit `db` rows and labeled the full `00:$0B8D-$0ED4` table as `GameTurnParamTable`.
  - Named the local game-turn schedule bytes at `$C6A9`, `$C6AA`, and `$C6AC` as `GAME_TURN_TABLE_INDEX`, `GAME_TURN_STEP_TIMER`, and `GAME_TURN_DELAY`.
  - Converted Bank 0 `00:$117C-$11EF` from apparent instructions to matching/result OAM templates, a score-bonus table, and a tile-base index table.
  - Labeled the following unreferenced but coherent code island at `00:$11F0-$1202` as `UnusedDrawVerticalTilePairUnlessFF`.
  - Named the drop-input animation state at `$C75D/$C75E/$C761/$C764/$C774`, including the two seven-entry cascade arrays used by `AnimateDropDown` and `AnimateDropUp`.
  - Created `docs/source_recovery/drop_animation_state.md` to document the recovered drop animation flow and confidence levels.
  - Named `COLUMN_TOP_ROWS` at `$C66A-$C66D` and the drop cursor frame animation bytes at `$C66F-$C670`.
  - Created `docs/source_recovery/column_state.md` to document the first-pass column top-row and drop cursor animation evidence.
- Files created/modified:
  - `docs/source_recovery/data_ranges.md`
  - `docs/source_recovery/sound_engine.md`
  - `docs/source_recovery/graphics_loads.md`
  - `docs/source_recovery/sprite_oam.md`
  - `docs/source_recovery/field_animation_state.md`
  - `docs/source_recovery/egg_counter.md`
  - `docs/source_recovery/link_state.md`
  - `docs/source_recovery/countdown_digit_buffers.md`
  - `docs/source_recovery/column_blink_state.md`
  - `docs/source_recovery/settings_blink_state.md`
  - `docs/source_recovery/vram_copy.md`
  - `docs/source_recovery/title_menu.md`
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
| Bank 1 tile string conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Title marker WRAM naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Field animation state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Egg counter state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Link state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Countdown digit buffer naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Column blink/rank state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Settings blink state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| VRAM copy slot naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Pre-play loop naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Title menu loop naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Small Bank 0 data island conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Game-turn parameter table conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Matching/result table conversion rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Drop animation state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Column state naming rebuild | `make -B` plus `cmp -s` | byte-identical ROM | exit `0`; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| BG map shadow slice-copy naming rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| 2P result mark tilemap naming rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| SCY/WY shadow HRAM naming rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Wave RAM and countdown blit destination rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Graphics VRAM and matching OAM destination rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Round-complete tilemap origin rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Result record row tilemap origin rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| 2P result layout tilemap origin rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Title screen BG layout origin rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| 2P field occupancy count path rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs | pass |
| Round-complete reveal helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs; raw `$Cxxx` count remains 0 | pass |
| Elapsed timer helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs; raw `$Cxxx` count remains 0 | pass |
| Link round-state helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs; raw `$Cxxx` count remains 0 | pass |
| Cursor/tilemap helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs; raw `$Cxxx` count remains 0 | pass |
| Sprite buffer/playfield HUD helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; SHA-256 `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253` for both ROMs; raw `$Cxxx` count remains 0 | pass |
| Playfield timer/link header helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; numbered placeholder labels removed; raw `$Cxxx` count remains 0 | pass |
| Playfield side-panel layout helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no raw direct branches | verifier returned OK; placeholder labels and old column-block helper name removed; raw `$Cxxx` count remains 0 | pass |
| Playfield HUD coordinate local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale local labels | verifier returned OK; targeted old playfield HUD local labels removed; raw `$Cxxx` count remains 0; generated local label count is 492 | pass |
| VBlank sound/timer local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale wave/timer/sound labels | verifier returned OK after restoring the vibrato intermediate branch; targeted stale labels removed; raw `$Cxxx` count remains 0; generated local label count is 472 | pass |
| Sound sequence parser local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale sound parser local labels | verifier returned OK; targeted old parser labels removed; raw `$Cxxx` count remains 0; generated local label count is 436 | pass |
| Egg text animation symbol sync rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale symbol aliases | verifier returned OK; symbol names match recovered source labels | pass |
| Gameplay input and fall-delay helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale helper aliases | verifier returned OK; previous helper names removed | pass |
| Playfield board/piece setup helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale setup aliases | verifier returned OK; previous setup helper names removed | pass |
| Selected-column piece staging helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale helper aliases | verifier returned OK; previous movement-style helper labels removed; raw `$Cxxx` count remains 0 | pass |
| Board scan target row helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale helper aliases | verifier returned OK; previous timer/speed-style helper labels removed; raw `$Cxxx` count remains 0 | pass |
| Sound command and pitch-slide helper label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale helper aliases | verifier returned OK; previous anonymous sound dispatch and pitch-slide helper labels removed; raw `$Cxxx` count remains 0 | pass |
| Drop animation cascade loop label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale drop-cascade aliases | verifier returned OK; previous anonymous drop-cascade jump labels removed; raw `$Cxxx` count remains 0 | pass |
| Bank 0 local control label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted anonymous labels removed; raw `$Cxxx` count remains 0 | pass |
| Final anonymous jump label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no `Jump_*` labels in Bank 0/1 real code/docs | verifier returned OK; `Jump_*` scan returned no matches; raw `$Cxxx` count remains 0 | pass |
| Bank 0 initial utility local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old `jr_000_*` labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 384 | pass |
| Bank 0 startup clear local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old startup clear labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 378 | pass |
| Bank 0 tilemap fill local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old tilemap fill labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 374 | pass |
| Bank 0 tilemap address carry label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old address carry labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 371 | pass |
| Bank 0 MainLoop and pause local label cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old state/load/pause labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 356 | pass |
| Bank 0 sprite-object wait and masked-count cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old masked-count and sprite-object labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 352 | pass |
| Bank 0 tile sprite and board draw local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old tile-sprite and board-draw labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 339 | pass |
| Bank 0 column blink sprite draw local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old column-sprite labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 333 | pass |
| Bank 0 drop animation completion local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old drop-completion labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 325 | pass |
| Bank 0 drop collision and position local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old drop collision/update labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 319 | pass |
| Bank 0 drop state board-pattern column-blink local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old drop-state, board-pattern, and column-blink labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 287 | pass |
| Bank 0 Multiply local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old Multiply local labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 284 | pass |
| Bank 0 game-state init and drop cursor local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old game-state init/drop-cursor labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 279 | pass |
| ProcessMatching animation local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old ProcessMatching labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 264 | pass |
| Matching score result local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old matching score/result labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 262 | pass |
| FillRect and gameplay display local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old FillRect/gameplay display labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 248 | pass |
| HandlePlayfieldInput local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old input/fast-fall labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 239 | pass |
| UpdateMatchState fall landing local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old fall/landing labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 224 | pass |
| Board piece setup local loop cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old board/piece setup labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 213 | pass |
| Board scan animation local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old board-scan labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 203 | pass |
| Round complete send display local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old round-complete/send/display labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 195 | pass |
| Piece display menu selection local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old piece-display/menu-selection labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 167 | pass |
| Link field rise blink and option UI local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old link/blink/option UI labels removed from source/docs; raw `$Cxxx` count remains 0; generated local label count is 157 | pass |
| Option marker and detached preplay local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted source/symbol labels | verifier returned OK; targeted old option/preplay labels removed from source/sym; raw `$Cxxx` count remains 0; generated local label count is 124 | pass |
| Serial/string/preplay-init/field-animation local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old serial/string/preplay-init/field-animation labels removed; raw `$Cxxx` count remains 0; generated local label count is 112 | pass |
| Link settings exchange and result-record init local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old link-settings/result-init labels removed; raw `$Cxxx` count remains 0; generated local label count is 106 | pass |
| Countdown digit buffer local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK; targeted old countdown buffer labels removed; raw `$Cxxx` count remains 0; generated local label count is 86 | pass |
| Round-end and link-result local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted local labels | verifier returned OK after moving the 1P round-end label back to the original branch target; targeted old round-end/rank/high-score/link-result labels removed; raw `$Cxxx` count remains 0; generated local label count is 36 | pass |
| Final Bank 0/1 generated local cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no generated `jr_000_*` label definitions | verifier returned OK; raw `$Cxxx` count remains 0; generated local label count is 0 | pass |
| BGM preview and fall-accel leftover cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted names | verifier returned OK; old BGM period, unreachable fall-accel, and orphan number-pair helper names removed | pass |
| Clear-only/write-only WRAM cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale targeted names | verifier returned OK; old egg/link/drop scratch names removed | pass |
| Score preserve/copy-only WRAM cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale score unknown names | verifier returned OK; score-adjacent preserved/copy-only bytes now use low-confidence unused names | pass |
| Sprite slot toggled-frame/fast-fall clamp cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no stale unresolved slot notes | verifier returned OK; raw `$Cxxx`, direct raw branches, and generated local label scans remain clean | pass |
| Reserved sprite object type 7 cleanup rebuild | `tools/verify_yoshi_build.sh` | byte-identical ROM and no old type-7 frame labels | verifier returned OK; type `$07` is documented as reserved/no confirmed producer | pass |
| High-bit sprite object variant cleanup rebuild | `tools/verify_yoshi_build.sh` plus targeted scans | byte-identical ROM and no stale high-bit object wording | verifier returned OK; both ROM SHA-256 values are `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`; raw `$Cxxx`, raw direct branch, generated local label, and targeted stale-name scans remain clean | pass |
| Landing placement sound/score cleanup rebuild | `tools/verify_yoshi_build.sh` plus targeted scans | byte-identical ROM and no stale landing raw immediates | verifier returned OK; both ROM SHA-256 values are `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`; raw `$Cxxx`, raw direct branch, generated local label, and `ld a, $1c` / `ld hl, $0005` scans remain clean | pass |
| UpdateMatchState return/row constant cleanup rebuild | `tools/verify_yoshi_build.sh` plus targeted scans | byte-identical ROM and no stale UpdateMatchState row/Y-step/overflow immediates | verifier returned OK; both ROM SHA-256 values are `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`; raw `$Cxxx`, raw direct branch, generated local label, and targeted `cp $02` / `add $08` / `cp $ff` scans remain clean in `UpdateMatchState` | pass |
| Raw direct branch scan | `rg -n 'call \\$|jp \\$|jr \\$' Yoshi/bank_000.asm Yoshi/bank_001.asm` | no matches | no matches | pass |

### Phase 5: Piece Display Shuffle And Initial Fill Constants
- **Status:** completed
- Actions taken:
  - Named the shared piece-display shuffle selector mask as
    `PIECE_DISPLAY_SHUFFLE_INDEX_MASK`.
  - Named the first code used by `InitPieceDisplayCodePool`.
  - Named the initial B-type board-fill pool offset and the
    `AvoidInitialBoardAdjacentDuplicate` adjacent-match wrap sentinel/value.
  - Updated piece-display, board-layout, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted stale-immediate scans for `ld c, $38`,
    `PIECE_DISPLAY_CODE_POOL + $03`, `ld a, $01`, and `cp $05` in the touched
    piece-display / initial-fill ranges returned no matches.
  - `git diff --check` passed.
- Note:
  - The first targeted stale scan attempt used bad shell escaping and produced
    an `rg` regex parse error; the command was rerun with single-quoted
    patterns and returned the expected no-match result.

### Phase 5: Piece Display Blink Constants
- **Status:** completed
- Actions taken:
  - Named the display-object blink scan count as
    `PIECE_DISPLAY_BLINK_SLOT_COUNT`.
  - Replaced the active object type check with the piece-display object type
    constant.
  - Named the blink-exempt state `$08` and frame toggle mask `$10`.
  - Updated piece-display, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted stale-immediate scan for the blink range returned no matches for
    `ld de, $0010`, `ld b, $08`, `cp $02`, `cp $07`, `cp $08`, or `xor $10`.
  - `git diff --check` passed.

### Phase 4/5: Board Tile Pattern Helper/Table Names
- **Status:** completed
- Actions taken:
  - Renamed the grid-piece pattern helper/table path to
    `GetGridPiecePatternOffset`, `CopyTilePatternRow4`, and
    `GridPiecePatternTable`.
  - Renamed the column-sprite pattern helper/table path to
    `GetColumnSpritePatternOffset`, `CopyEncodedTilePatternRow4SkipFF`, and
    `ColumnSpritePatternTable`.
  - Added record-size constants for the 8-byte grid-piece records, 12-byte
    column-sprite records, and the `$30` column-sprite frame block.
  - Synced `Yoshi/yoshi.sym` and updated board-layout, column-state,
    column-blink, sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted stale-name scan for the old table/offset/copy helper names
    returned no matches.
  - Targeted stale-immediate scan in the pattern helper/draw range returned no
    matches for `ld de, $0010`, `ld a, $04`, or `ld a, $30`.
  - `git diff --check` passed.
- Note:
  - One intermediate targeted scan matched the new column-sprite table name
    because the pattern used a broad substring; it was rerun with exact old
    names and returned no matches.

### Phase 4/5: Board Tile Pattern Record/Block Split
- **Status:** completed
- Actions taken:
  - Split `GridPiecePatternTable` into nine 8-byte
    `GridPiecePatternPayload0..8` records.
  - Split `ColumnSpritePatternTable` into `ColumnSpritePatternFrame2Block`,
    `ColumnSpritePatternFrame1Block`, four 12-byte records per block, and the
    16-byte unreached column-sprite tail.
  - Added the record-count, frame-block-count, and tail-size constants that
    describe these boundaries.
  - Split the matching `Yoshi/yoshi.sym` data ranges and updated board-layout,
    column-blink, sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted stale scan for the old unsplit data ranges and old helper/table
    names returned no matches after rephrasing planning notes to avoid exact
    stale-name literals.
  - `git diff --check` passed.

### Phase 4/5: DrawColumnSprite Static-Dead Alternate Fragment
- **Status:** completed
- Actions taken:
  - Marked the alternate row fragment after the unconditional branch in
    `DrawColumnSprite` as `UnreachedColumnSpriteAlternateRowFragment`.
  - Renamed its internal branch labels to `UnreachedColumnSpriteWrapRow` and
    `UnreachedColumnSpriteContinueAtRow1`.
  - Updated board-layout, column-blink, sprite/OAM, findings, task-plan, and
    work-estimate notes to record that the live column-blink path cannot select
    the unreached column-sprite tail.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted stale scan for the old alternate-row labels returned no matches.
  - `rg -n '^\\s*call DrawColumnSprite$' Yoshi/bank_000.asm Yoshi/bank_001.asm`
    found one confirmed caller, inside `UpdateColumnBlinkState`.
  - `git diff --check` passed.

### Phase 4/5: Unreached Column Sprite Pattern Tail
- **Status:** completed
- Actions taken:
  - Renamed the 16-byte column-sprite tail to
    `UnreachedColumnSpritePatternTailRows`.
  - Replaced the generic tail-size constant with
    `COLUMN_SPRITE_PATTERN_UNREACHED_TAIL_SIZE`.
  - Added `COLUMN_SPRITE_PATTERN_LIVE_SIZE` for the two live `$30`-byte frame
    blocks.
  - Updated board-layout, column-blink, sprite/OAM, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Exact stale scan for the old tail label, old tail-size constant, and old
    alternate-row labels returned no matches.
  - `git diff --check` passed.
- Note:
  - A first broad stale scan matched the new `Unreached...` tail label as a
    substring; rerunning with exact label-boundary matching returned no
    matches.

### Phase 4/5: Grid Piece Payload And Piece Display Code Constants
- **Status:** completed
- Actions taken:
  - Renamed the old grid-piece record label family to
    `GridPiecePatternPayload0..8` in source and `Yoshi/yoshi.sym` to reflect
    that `DrawGridPiece` indexes the 8-byte records directly by the A-register
    payload.
  - Renamed the old grid-piece record-count constant to
    `GRID_PIECE_PATTERN_PAYLOAD_COUNT`.
  - Added explicit `PIECE_DISPLAY_CODE_1`, `PIECE_DISPLAY_CODE_2`,
    `PIECE_DISPLAY_CODE_3`, `PIECE_DISPLAY_CODE_4`, and
    `PIECE_DISPLAY_CODE_8` constants for the `ProcessMenuSelection` return
    tails.
  - Rebased `PIECE_DISPLAY_CODE_FIRST` and
    `PIECE_DISPLAY_BLINK_EXEMPT_STATE` on those narrower code constants.
  - Updated board-layout, sprite/OAM, piece-display, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted stale scan for the old grid-piece record label family and old
    record-count constant returned no matches.
  - Targeted scan over the `ReturnPieceDisplayCode*` block returned no raw
    `$01/$02/$03/$04/$08` return immediates.
  - `git diff --check` passed.

### Phase 4/5: Drop Collision Grid-Column Sentinel Constants
- **Status:** completed
- Actions taken:
  - Added `SPRITE_OBJECT_GRID_COLUMN_UNSET` for the `$FF` sentinel in logical
    sprite object byte `+$05`.
  - Replaced the two drop-collision writes that invalidate
    `SPRITE_OBJECT_GRID_COLUMN` after shifting `SPRITE_OBJECT_BASE_X`.
  - Added `DROP_COLLISION_SPRITE_X_STEP`,
    `DROP_COLLISION_Y_OVERLAP_LIMIT`,
    `DROP_COLLISION_ADVANCE_FROM_BASE_Y`,
    `DROP_ANIM_STATE_INACTIVE`, and `DROP_ANIM_CLEAR_SIZE`.
  - Reused `BOARD_COLUMN_STRIDE` for the adjacent-column swap address advance.
  - Updated drop-animation, sprite/OAM, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted scan over `AnimateDropping` through `ClearAnimState` shows the new
    drop-state/collision constants at the intended sites.
  - `DROP_ANIM_STATE_INACTIVE` appears only in the two drop-cascade state-clear
    sites.
  - `git diff --check` passed.
- Error handled:
  - The first broad `$00` replacement also touched `Multiply` scratch
    initialization. It was restored to raw `$00` before verification; the
    targeted `DROP_ANIM_STATE_INACTIVE` scan now shows only the intended
    drop-cascade sites.

### Phase 4/5: Round Complete Reveal Sound And Transition Constants
- **Status:** completed
- Actions taken:
  - Added `SND_ROUND_COMPLETE_REVEAL` and
    `SND_ROUND_COMPLETE_MAJOR_REVEAL` for sound IDs `$12` and `$16`.
  - Renamed the matching Bank 1 sound index labels to
    `SoundIndexEntry_RoundCompleteReveal` and
    `SoundIndexEntry_RoundCompleteMajorReveal`.
  - Added round-complete transition constants for the tile-slot count,
    transition frame start, send-frame waits, frame-toggle mask, major reveal
    frame, and field-animation active value.
  - Replaced the corresponding raw immediates in the 2P round-complete
    transition path, the single-player round-complete tile-slot initializer, and
    the A-type bonus reveal branches.
  - Updated sound-engine, field-animation, sprite/OAM, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted round-complete source scan shows the new constants in the
    transition, tile-slot, and bonus reveal call sites.
  - `git diff --check` passed.

### Phase 4/5: A-Type Round Complete Bonus Score And Manual OAM Constants
- **Status:** completed
- Actions taken:
  - Added constants for the A-type round-complete 500/200/100/50 bonus score
    deltas and their manual-OAM left-tile/Y arguments.
  - Added constants for the shared round-complete tile group base X/Y values,
    bonus right tile, right-tile X step, animation frame count, hold frame
    count, and manual-OAM pair byte size.
  - Replaced the matching raw immediates in `ShowRoundComplete`, the A-type
    bonus threshold branches, `RevealRoundComplete2x2Block`, and
    `AddScoreAndAnimateManualOamPair`.
  - Updated sprite/OAM, memory-map, data-range, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted round-complete bonus scan shows the new bonus/base/manual-OAM
    constants at the intended sites and no old targeted raw argument
    immediates.
  - `git diff --check` passed.

### Phase 3/4/5: Start Button, Link Role, And Link Serial Constants
- **Status:** completed
- Actions taken:
  - Added `LINK_ROLE_MASTER` for the `$01` link role and used it at master-role
    comparisons/stores across title, pre-play, serial, pause, settings, and
    result-confirm paths.
  - Replaced remaining Start-button raw bit/value tests with the RGBDS hardware
    constants `PADB_START` and `PADF_START`.
  - Added `SERIAL_TRANSFER_INTERNAL_CLOCK`,
    `SERIAL_TRANSFER_EXTERNAL_CLOCK`, `LINK_CONFIRM_BYTE`, and
    `LINK_PAUSE_PACKET`; replaced the matching link serial control values while
    leaving unrelated sound-parser `$F0` handling untouched.
  - Updated link-state, title-menu, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted scans show no remaining `bit 3, a`, `res 3, a`, `and $08`, direct
    `LINK_ROLE`/`cp $01`, or raw `$01/$02` stores into `LINK_ROLE`.
  - Targeted link-serial scans show no remaining link-side raw `ld a, $80/$81`
    into `rSC`, raw `$55` confirm-byte checks/writes, or raw `$F0` pause
    packet checks/writes; the only remaining `cp $F0` match is the unrelated
    sound parser command check.
  - `git diff --check` passed.

### Phase 4/5: 2P Result Screen Tile And Panel Constants
- **Status:** completed
- Actions taken:
  - Added constants for the 2P result/high-score screen's role-swapped
    header/badge tile bases, BG clear tile, status clear/text tile bases,
    terminal outcome tile pair, wait-panel tile pairs, score clear/fill areas,
    and confirm-panel tile/rect values.
  - Replaced the matching raw immediates in `UpdateLinkResultMarksAndScreen`, the terminal
    2P result branches, `WaitLinkStartConfirm`,
    `DrawLinkResultConfirmPanelsAndWait`,
    `DrawLinkResultRoleStatusStrip`, `FillLinkResultWideScoreArea`, and
    `FillLinkResultNarrowScoreArea`.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted 2P result-screen scan shows the new `LINK_RESULT_*` constants at
    the intended sites and no old targeted tile/rect immediates in the
    `BuildLinkResultScreen` through `FillLinkResultNarrowScoreArea` range.
  - `git diff --check` passed.

### Phase 4/5: 2P Result Sound ID Constants
- **Status:** completed
- Actions taken:
  - Added `SND_LINK_RESULT_NONZERO`, `SND_LINK_RESULT_ZERO`,
    `SND_LINK_RESULT_CONFIRM_WAIT`, and `SND_LINK_RESULT_MENU_WAIT`.
  - Added matching sound-index aliases:
    `SoundIndexEntry_LinkResultNonzero`,
    `SoundIndexEntry_LinkResultZero`,
    `SoundIndexEntry_LinkResultConfirmWait`, and
    `SoundIndexEntry_LinkResultMenuWait`.
  - Replaced the raw `$58/$5B/$5E/$62` sound IDs in
    `CheckTerminalLinkResultScreen`, `WaitLinkStartConfirm`, and
    `WaitTerminalLinkResultMenuConfirm`, including the active-sound guard
    comparisons.
  - Updated sound-engine, link-state, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted link-result sound scan shows the new `SND_LINK_RESULT_*`
    constants and no old raw `$58/$5B/$5E/$62` sound IDs in the terminal/result
    wait range.
  - `git diff --check` passed.

### Phase 4/5: Matching Animation Sound ID Constants
- **Status:** completed
- Actions taken:
  - Added `SND_MATCHING_INTRO_BLINK`,
    `SND_MATCHING_RESULT_PANEL_BLINK`, and `SND_MATCHING_OAM_SLIDE`.
  - Added matching sound-index aliases:
    `SoundIndexEntry_MatchingIntroBlink`,
    `SoundIndexEntry_MatchingResultPanelBlink`, and
    `SoundIndexEntry_MatchingOamSlide`.
  - Replaced the raw `$2B/$2C/$29` sound IDs in `ProcessMatching` at the intro
    blink counter wrap, result-panel blink counter wrap, and matching OAM slide
    start.
  - Updated sound-engine, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted `ProcessMatching` sound scan shows the new `SND_MATCHING_*`
    constants and no old raw `$29/$2B/$2C` sound IDs in the matching animation
    range.
  - `git diff --check` passed.

### Phase 4/5: ProcessRoundResultAndEnterRoundEnd Result Sound ID Constants
- **Status:** completed
- Actions taken:
  - Added `SND_RESULT_1P_NO_RANK`, `SND_RESULT_1P_RANKED`,
    `SND_RESULT_2P_NONZERO_RANK`, and `SND_RESULT_2P_ZERO_RANK`.
  - Added matching sound-index aliases:
    `SoundIndexEntry_Result1PNoRank`,
    `SoundIndexEntry_Result1PRanked`,
    `SoundIndexEntry_Result2PNonzeroRank`, and
    `SoundIndexEntry_Result2PZeroRank`.
  - Replaced the raw `$66/$69/$6F/$71` sound IDs in
    `ProcessRoundResultAndEnterRoundEnd`, keeping the single-player ranked/no-rank branches
    separate from the two-player nonzero/zero result branches.
  - Updated sound-engine, result-record, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted `ProcessRoundResultAndEnterRoundEnd` sound scan shows the new `SND_RESULT_*`
    constants and no old raw `$66/$69/$6F/$71` sound IDs in the result sound
    branch range.
  - `git diff --check` passed.

### Phase 4/5: Link Field-Rise Sound ID Constant
- **Status:** completed
- Actions taken:
  - Added `SND_LINK_FIELD_RISE` for sound ID `$11`.
  - Added `SoundIndexEntry_LinkFieldRise` as the matching sound-index alias.
  - Replaced the raw `$11` in `PlayPendingFieldRiseSound`, the path that
    consumes `LINK_PENDING_FIELD_RISE` and returns the adjusted `SCREEN_STATE`.
  - Updated sound-engine, link-state, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted field-rise sound scan shows `SND_LINK_FIELD_RISE` immediately
    before `PlaySound` and no old raw `$11` in that branch range.
  - `git diff --check` passed.

### Phase 4/5: Link Field-Rise Screen-State Limit Constant
- **Status:** completed
- Actions taken:
  - Added `LINK_FIELD_RISE_SCREEN_STATE_LIMIT` for the `$04` cap used while
    consuming `LINK_PENDING_FIELD_RISE`.
  - Replaced both `$04` immediates in `ConsumePendingFieldRise`: the first
    computes remaining capacity from `SCREEN_STATE`, and the second returns
    the capped state after carrying leftover pending rise count forward.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted field-rise screen-state scan shows
    `LINK_FIELD_RISE_SCREEN_STATE_LIMIT` in both cap sites and no old raw `$04`
    in the touched range.
  - `git diff --check` passed.

### Phase 4/5: ProcessRoundResultAndEnterRoundEnd Object Clear Span Constant
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_OBJECT_SLOT_CLEAR_BYTES` for the `$40`-byte clear
    span that starts at `SPRITE_OBJECT_SLOT_10`.
  - Replaced the raw `$40` byte count in `ClearRoundCompleteObjectSlotsLoop`.
  - Updated result-record, sprite/OAM, findings, task-plan, and work-estimate
    notes to record that `ProcessRoundResultAndEnterRoundEnd` clears slots 10-13 before
    entering the round-end result flow.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted object-clear scan shows `ROUND_COMPLETE_OBJECT_SLOT_CLEAR_BYTES`
    in the clear loop and no old raw `$40` in the touched range.
  - `git diff --check` passed.

### Phase 4/5: ProcessRoundResultAndEnterRoundEnd Round-End Wait Timer Constant
- **Status:** completed
- Actions taken:
  - Added `ROUND_END_WAIT_INITIAL_FRAMES` for the `$003C` little-endian value
    seeded into `ROUND_END_WAIT_TIMER`.
  - Replaced the raw `$3C` low byte in `EnterRoundEndState`.
  - Updated result-record, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted round-end wait scan shows `ROUND_END_WAIT_INITIAL_FRAMES` in the
    timer seed path and no old raw `$3C` in the touched range.
  - `git diff --check` passed.

### Phase 4/5: Round-End Result Delay Constant
- **Status:** completed
- Actions taken:
  - Added `ROUND_END_RESULT_DELAY_FRAMES` for the `$78` value written to
    `VBLANK_BUSY` after result flow settles.
  - Replaced both round-end delay literals: the two-player tail after clearing
    `SERIAL_DONE` / `LINK_SEND`, and the single-player tail before the A/B-type
    round-complete continuation.
  - Updated result-record, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted round-end result-delay scan shows `ROUND_END_RESULT_DELAY_FRAMES`
    in both `VBLANK_BUSY` seed paths and no old raw `$78` in the touched range.
  - `git diff --check` passed.

### Phase 4/5: Result Rank Display Constants
- **Status:** completed
- Actions taken:
  - Added `RESULT_RANK_TOP_COORD`, `RESULT_RANK_BOTTOM_COORD`,
    `RESULT_RANK_TILE_RUN_LENGTH`, `RESULT_RANK_TOP_TILE_BASE`, and
    `RESULT_RANK_BOTTOM_TILE_BASE` for `DrawScoreRanking`.
  - Added `RESULT_RANK_SPECIAL_POSITION_CODE` for the `$43` value normalized to
    `RESULT_RANK_FIRST_PLACE` before drawing the rank tile runs.
  - Replaced the raw rank display coordinates, tile-run length, tile bases, and
    special-position comparisons in `DrawScoreRanking`.
  - Updated column-blink/rank, result-record, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted rank-display scan shows only `RESULT_RANK_*` constants in the
    touched `DrawScoreRanking` range.
  - `git diff --check` passed.

### Phase 4/5: Round-End Sprite Object Clear Span Constant
- **Status:** completed
- Actions taken:
  - Added `ROUND_END_SPRITE_OBJECT_CLEAR_BYTES` for the `$EF` byte span cleared
    from `SPRITE_OBJECTS` by `ClearRoundEndSpriteObjectsAndRecord`.
  - Replaced the raw `$EF` clear count in `ClearRoundEndSpriteObjectsLoop`.
  - Updated sprite/OAM, result-record, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted round-end sprite-object clear scan shows
    `ROUND_END_SPRITE_OBJECT_CLEAR_BYTES` in the clear loop and no old raw
    `$EF` in the touched range.
  - `git diff --check` passed.

### Phase 4/5: 2P Result Graphics Copy Size Constants
- **Status:** completed
- Actions taken:
  - Added `BANK3_LINK_RESULT_TILE_BLOCK_COPY_SIZE` for the two `$0800` base
    tile-block copies in `BuildLinkResultScreen`.
  - Added `BANK3_LINK_RESULT_OVERLAY_9470_COPY_SIZE` and
    `BANK3_LINK_RESULT_OVERLAY_8800_COPY_SIZE` for the conditional terminal
    overlay copies.
  - Replaced the raw `$0800/$0390/$0740` sizes in the
    `UpdateLinkResultMarksAndScreen` / `BuildLinkResultScreen` graphics load path.
  - Updated graphics-load, link-state, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Targeted high-score graphics-copy scan shows only the new
    `BANK3_LINK_RESULT_*` constants in the touched copy-size operands.
  - `git diff --check` passed.

### Phase 3/4: Link Result Confirm Wait Branch Cleanup
- **Status:** completed
- Actions taken:
  - Added `LINK_RESULT_WAIT_PANEL_ALT_START_FRAME` and
    `LINK_RESULT_WAIT_PANEL_ANIM_PERIOD` for the `$1E/$3C` frame thresholds
    used by `WaitLinkStartConfirm`.
  - Replaced the final three anonymous Bank 0/1 `@+` / `@-` relative branches
    with named targets: `WaitLinkStartConfirm` and
    `ContinueLinkConfirmWait`.
  - Synced `Yoshi/yoshi.sym` with the `00:$33F7/$33FA` link-confirm wait
    labels.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted link-confirm wait scan shows `WaitLinkStartConfirm`,
    `ContinueLinkConfirmWait`, and the new `LINK_RESULT_WAIT_PANEL_*`
    constants in the touched range.
  - `git diff --check` passed.

### Phase 2/3: Low-Level Joypad And LCD Utility Constants
- **Status:** completed
- Actions taken:
  - Replaced the raw P1 select/mask/released values in `ReadJoypad` and
    `ReadJoypadButtons` with `P1F_GET_DPAD`, `P1F_GET_BTN`,
    `P1F_GET_NONE`, `P1_INPUT_BITS_MASK`, and
    `P1_INPUT_BITS_RELEASED`.
  - Added `OAM_DMA_HRAM_LOW` and `OAM_DMA_ROUTINE_SIZE` for the
    `SetupOAMDMA` HRAM copy loop.
  - Replaced the LCD-off utility immediates with `IEB_VBLANK`,
    `LCD_OFF_SAFE_SCANLINE`, and `LCDC_DISABLE_MASK`.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted low-level utility scan shows the new P1/OAM/LCD constants in the
    touched `ReadJoypad` / `SetupOAMDMA` / `LCDOff` range.
  - `git diff --check` passed.

### Phase 2/3: Startup Hardware Initialization Constants
- **Status:** completed
- Actions taken:
  - Added startup constants for the default BG/OBJ palettes, stack top, HRAM
    clear size, enabled interrupts, offscreen window Y, left-edge window X,
    hardware tilemap page high bytes, hardware tilemap clear tile/size, and the
    final LCDC runtime flags.
  - Replaced the corresponding raw immediates in `Init`, `StartGame`, and
    `FillTilemap`.
  - Updated memory-map, VRAM-copy, findings, task-plan, and work-estimate notes.
- Test result:
  - First verifier attempt failed because `STACK_TOP` was defined before
    `WRAM_START` / `WRAM_SIZE`; moving it below the WRAM definitions fixed the
    assembly error.
  - `tools/verify_yoshi_build.sh` passed after the definition-order fix.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted startup scan shows the new palette/stack/HRAM/interrupt/window/
    tilemap/LCDC constants in the touched `Init` / `StartGame` /
    `FillTilemap` range.
  - `git diff --check` passed.

### Phase 2/3/4: BG Map Shadow Fill Tile Constants
- **Status:** completed
- Actions taken:
  - Added `TITLE_BG_SHADOW_CLEAR_TILE` for the `$E0` fill used by
    `FillTitleTilemap`.
  - Added `GAME_BG_SHADOW_CLEAR_TILE` as the game-screen alias of
    `FIELD_OCCUPANCY_EMPTY_TILE` for the `$4A` fill used by `FillGameTilemap`.
  - Replaced the two raw fill-tile immediates in the shared
    `BeginBgMapShadowFill` callers.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted BG shadow fill scan shows `GAME_BG_SHADOW_CLEAR_TILE` and
    `TITLE_BG_SHADOW_CLEAR_TILE` in `FillGameTilemap` / `FillTitleTilemap`.
  - `git diff --check` passed.

### Phase 4: Bank 2 Graphics Copy Size Constants
- **Status:** completed
- Actions taken:
  - Added `BANK2_GAME_TILE_SET_COPY_SIZE`,
    `BANK2_TITLE_TILE_SET_COPY_SIZE`, `BANK2_COMMON_TILE_SET_COPY_SIZE`,
    `BANK2_PREPLAY_MENU_OVERLAY_COPY_SIZE`,
    `BANK2_TWO_PLAYER_SHARED_TILES_COPY_SIZE`, and
    `BANK2_TWO_PLAYER_NONMASTER_TILES_COPY_SIZE`.
  - Replaced the raw `$0800/$1000/$0200/$0260` copy sizes in the title init,
    pre-play init, and `LoadGameTiles` Bank 2 load paths.
  - Updated graphics-load, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted Bank 2 graphics-copy scan shows only `BANK2_*_COPY_SIZE`
    constants in the touched title/pre-play/gameplay load paths.
  - `git diff --check` passed.

### Phase 4: Bank 3 Matching And Result Graphics Copy Size Constants
- **Status:** completed
- Actions taken:
  - Added `BANK3_MATCHING_TILE_BLOCK_COPY_SIZE` for the three `$0800`
    `ProcessMatching` tile-block copies.
  - Added `BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE` for the two `$0800`
    `SetupResultRecordScreen` tile-block copies.
  - Replaced the raw matching/result-record Bank 3 copy sizes in Bank 0.
  - Updated graphics-load, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted Bank 3 matching/result-record graphics-copy scan shows only the
    new `BANK3_*_TILE_BLOCK_COPY_SIZE` constants in the touched load paths.
  - `git diff --check` passed.

### Phase 4: ProcessMatching Setup And OAM Constants
- **Status:** completed
- Actions taken:
  - Added `MATCHING_STATE_COUNT` and `MATCHING_LAST_STATE` for the
    `STATE_TRANSITION` clamp before the matching/result setup.
  - Added `MATCHING_BG_VRAM_CLEAR_SIZE`, `MATCHING_BG_CLEAR_TILE`, and
    `MATCHING_LCDC_FLAGS` for the setup path that clears BG map VRAM/shadow,
    loads Bank 3 matching tiles, and enables the matching display mode.
  - Added `MATCHING_MIDDLE_OAM_ENTRY_COUNT`,
    `MATCHING_PAIR_OAM_ENTRY_COUNT`, `MATCHING_MIDDLE_OAM_TEMPLATE_SIZE`, and
    `MATCHING_PAIR_OAM_TEMPLATE_SIZE` for the middle/top/final matching OAM
    template copies and entry scans.
  - Replaced the corresponding raw immediates in `ProcessMatching`, including
    the OAM-entry stride uses in the matching slide/final movement path.
  - Updated graphics-load, sprite/OAM, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ProcessMatching` setup/OAM stale-immediate scan returned no
    matches for the touched raw values in the routine.
  - `git diff --check` passed.

### Phase 4: ProcessMatching Animation Timing And Panel Constants
- **Status:** completed
- Actions taken:
  - Added constants for the intro scroll start/count, intro blink period/split,
    and post-intro wait.
  - Added constants for the result-panel scroll start/count, blink period/split,
    staged fill tiles, shared panel rectangle sizes, right-edge row count, and
    per-stage waits.
  - Added constants for the matching OAM slide frame count, signed X steps,
    final OAM tile base, final upward movement length, and score-application
    wait.
  - Replaced the matching animation immediates in `ProcessMatching` while
    keeping the `ShiftMatchingOamPairX` call-site operand named as an X step
    rather than an entry count.
  - Updated memory-map, sprite/OAM, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ProcessMatching` animation stale-immediate scan returned no
    matches for the touched raw timing/panel/OAM values in the routine.
  - `git diff --check` passed.

### Phase 4: UpdateLevel Result Display Constants
- **Status:** completed
- Actions taken:
  - Added `MATCHING_SCORE_LCDC_FLAGS` for the LCDC value restored after the
    matching score display wait.
  - Added result display constants for score/level/time label tile bases,
    shared label rectangle size, time-label rectangle size, score digit count,
    low-nibble digit mask, digit tile base, speed tile base, and time separator
    tile.
  - Replaced the corresponding raw immediates in `UpdateLevel` and the matching
    score tail. The previous `ld bc, HeaderLogo` uses are now explicit
    `RESULT_LABEL_RECT_SIZE` loads rather than relying on the `$0104` header
    address as a rectangle size.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `UpdateLevel` stale-immediate scan returned no matches for the
    touched result label/digit/LCDC raw values in the routine.
  - `git diff --check` passed.

### Phase 3/4: WaitAnyButtonPress Helper Rename
- **Status:** completed
- Actions taken:
  - Added `PADF_ANY_BUTTON` as the A/B/Select/Start button mask for
    `JOYPAD_PRESSED`.
  - Renamed misleading `FillRectAlt` to `WaitAnyButtonPress`.
  - Updated the matching score tail and result-record no-inserted-label input
    path to call/jump to `WaitAnyButtonPress`.
  - Synced `Yoshi/yoshi.sym` at `00:$1240`.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted old-label scan returned no `FillRectAlt` matches in Bank 0/1
    source or `Yoshi/yoshi.sym`; docs only mention it as the former name.
  - `git diff --check` passed.

### Phase 3/4: Result Record Blink Button Mask
- **Status:** completed
- Actions taken:
  - Replaced the remaining raw `and $0f` immediately after
    `JOYPAD_PRESSED` in `PollResultRecordBlinkInput` with `PADF_ANY_BUTTON`.
  - Left the other Bank 0 `$0f` masks unchanged because they are link setting
    nibble splits, result-record digit masking, countdown high-bit cleanup, or
    BCD/tile digit handling rather than button masks.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - A targeted `awk` scan found no remaining Bank 0/1 sequence where
    `ldh a, [JOYPAD_PRESSED]` is immediately followed by raw `and $0f`.
  - `git diff --check` passed.

### Phase 4: Result Record Label Blink Timing Constants
- **Status:** completed
- Actions taken:
  - Added `RESULT_RECORD_LABEL_BLINK_ALT_START_FRAME` for the selected-label
    half of the result-record blink cycle.
  - Added `RESULT_RECORD_LABEL_BLINK_PERIOD` for the wrap period of the
    `STATE_TRANSITION` blink counter.
  - Replaced the raw `$1E/$3C` comparisons in `BlinkResultRecordLabelLoop`.
  - Updated result-record, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted result-record blink timing scan shows
    `RESULT_RECORD_LABEL_BLINK_ALT_START_FRAME` and
    `RESULT_RECORD_LABEL_BLINK_PERIOD` in the touched loop.
  - `git diff --check` passed.

### Phase 4: Result Record Digit Rendering Constants
- **Status:** completed
- Actions taken:
  - Added result-record digit count constants for score, level, A-type detail,
    and B-type timer pairs.
  - Added leading-zero policy constants for suppressed and shown runs, plus the
    final-digit guard that forces all-zero runs to display one zero.
  - Added result-record digit mask, digit tile base, B-type timer separator
    tile, and the post-render row delta.
  - Replaced the corresponding raw immediates in `DrawStoredResultRecords` and
    `DrawResultRecordDigitRun`.
  - Updated result-record, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted result-record digit rendering scan found no remaining raw
    `$05/$02/$03/$01/$00/$7A/$0019/$0F/$41` immediates in the touched render
    routine range.
  - Targeted constant scan shows the new `RESULT_RECORD_*` digit-rendering
    constants in `Yoshi/constants.inc`, `Yoshi/bank_000.asm`, and matching
    docs.
  - `git diff --check` passed.

### Phase 4: Result Record Staging And Comparison Constants
- **Status:** completed
- Actions taken:
  - Added `RESULT_RECORD_EMPTY_HEAD` for the `$FF` marker seeded by
    `RefreshField` and detected by the insert/render paths.
  - Added result-record comparison helpers for the first rank, level offset,
    and B-type four-digit detail count.
  - Reused the score, level, A-type detail, row-count, record-size, and digit
    mask constants in `ClearField`, `MaskCurrentResultRecordDigits`, and
    `ScanResultRecordInsertPositionLoop`.
  - Updated result-record, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted result-record staging/comparison scan found no remaining raw
    `$FF/$0005/$0004/$0F/$03/$01/$05/$02/$000B/$04` immediates in the
    touched source range.
  - Targeted constant scan shows the new `RESULT_RECORD_*` staging/comparison
    constants in `Yoshi/constants.inc`, `Yoshi/bank_000.asm`, and matching
    docs.
  - `git diff --check` passed.

### Phase 4: Result Record Palette Fade Timing Constants
- **Status:** completed
- Actions taken:
  - Added `RESULT_RECORD_PALETTE_FADE_STEP_COUNT` for the four palette values
    consumed from `ResultRecordPaletteSequence`.
  - Added `RESULT_RECORD_PALETTE_FADE_WAIT_FRAMES` for the per-step VBlank
    delay in `FadeInResultRecordPalette`.
  - Replaced the raw `$04/$10` loop count and wait count.
  - Updated result-record, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted result-record palette fade scan shows
    `RESULT_RECORD_PALETTE_FADE_STEP_COUNT` and
    `RESULT_RECORD_PALETTE_FADE_WAIT_FRAMES` in the touched loop, with no raw
    `$04/$10` fade-loop immediates left there.
  - `git diff --check` passed.

### Phase 4: Result Record Setup Fill Tile And Palette Value Constants
- **Status:** completed
- Actions taken:
  - Added setup fill-tile constants for the result-record BG shadow clear,
    screen header, type label, and B-type type-label patch.
  - Named the four `ResultRecordPaletteSequence` bytes as
    `RESULT_RECORD_PALETTE_FADE_VALUE_0..3`.
  - Replaced the corresponding raw immediates in `SetupResultRecordScreen` and
    `ResultRecordPaletteSequence`.
  - Updated result-record, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted result-record setup scan shows the new setup fill-tile and
    palette-value constants in the touched code/data range, with no raw
    `$02/$00/$24/$2A/$40/$90/$E4` setup/palette immediates left there.
  - Targeted constant scan shows the new constants in `Yoshi/constants.inc`,
    `Yoshi/bank_000.asm`, and matching docs.
  - `git diff --check` passed.

### Phase 4: 2P Settings Link Packet Nibble Mask
- **Status:** completed
- Actions taken:
  - Added `LINK_SETTINGS_NIBBLE_MASK` for the low-nibble mask used after
    swapping the received packed level/speed settings byte.
  - Replaced the two raw `$0F` masks in `UpdateGameField` when unpacking
    `LINK_RECV_LEVEL` and `LINK_RECV_SPEED`.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `UpdateGameField` scan shows both receive-side masks now use
    `LINK_SETTINGS_NIBBLE_MASK`, with no raw `$0F` in the touched unpack path.
  - Targeted constant scan shows `LINK_SETTINGS_NIBBLE_MASK` in
    `Yoshi/constants.inc`, `Yoshi/bank_000.asm`, and matching docs.
  - `git diff --check` passed.

### Phase 4: 2P Settings Option Count Table
- **Status:** completed
- Actions taken:
  - Renamed the old max-value table label to `LinkSettingsOptionCountTable`
    because the values are compared against the incremented candidate and act
    as exclusive upper bounds.
  - Added `LINK_SETTINGS_LEVEL_OPTION_COUNT` and
    `LINK_SETTINGS_SPEED_OPTION_COUNT` for the table entries.
  - Updated `Yoshi/yoshi.sym`, link-state, settings-blink, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted old-name scan returns no matches in source, symbols, and recovery
    docs.
  - Targeted option-count scan shows `LinkSettingsOptionCountTable` and
    `LINK_SETTINGS_LEVEL_OPTION_COUNT` / `LINK_SETTINGS_SPEED_OPTION_COUNT` in
    `Yoshi/constants.inc`, `Yoshi/bank_000.asm`, `Yoshi/yoshi.sym`, and
    matching docs.
  - `git diff --check` passed.

### Phase 4: 1P Option Count Tables
- **Status:** completed
- Actions taken:
  - Renamed the detached option table to `DetachedPreplayOptionCountTable`.
  - Renamed the live 1P pre-play table to `PreplayLoopOptionCountTable` and
    synced `Yoshi/yoshi.sym`.
  - Added `OPTION_GAME_TYPE_OPTION_COUNT`, `OPTION_LEVEL_OPTION_COUNT`,
    `OPTION_SPEED_OPTION_COUNT`, and `OPTION_BGM_OPTION_COUNT` for the table
    entries used as exclusive upper bounds.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted old option-table name scan returns no matches in source, symbols,
    and recovery docs.
  - Targeted option-count scan shows `DetachedPreplayOptionCountTable`,
    `PreplayLoopOptionCountTable`, and the four `OPTION_*_OPTION_COUNT`
    constants in `Yoshi/constants.inc`, `Yoshi/bank_000.asm`,
    `Yoshi/yoshi.sym`, and matching docs.
  - `git diff --check` passed.

### Phase 4: 1P Option Cursor Row Constants
- **Status:** completed
- Actions taken:
  - Added `MENU_CURSOR_ROW_GAME_TYPE`, `MENU_CURSOR_ROW_LEVEL`,
    `MENU_CURSOR_ROW_SPEED`, `MENU_CURSOR_ROW_BGM`, and
    `MENU_CURSOR_ROW_COUNT` for the 1P option cursor.
  - Added `MENU_CURSOR_UNDERFLOW_SENTINEL` for the detached pre-play cursor
    wraparound path.
  - Added `OPTION_BGM_OFF_VALUE` for BGM option value 3 and
    `OPTION_BGM_ADDR_LO` for the detached path's low-byte comparison after
    `GetArrayElement`.
  - Replaced the corresponding raw row/BGM values in detached and live 1P
    pre-play option input/drawing paths.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted detached/live 1P option input and selected-row drawing scans show
    the new cursor-row, BGM-off, and BGM-address-low constants in the touched
    paths.
  - Targeted constant scan shows the new names in `Yoshi/constants.inc`,
    `Yoshi/bank_000.asm`, and matching docs.
  - `git diff --check` passed.

### Phase 4: BGM Preview Timer And Period Constants
- **Status:** completed
- Actions taken:
  - Added `BGM_PREVIEW_RESET_VALUE` for the value written to both BGM preview
    bytes by `ResetSettings`.
  - Added `BGM_PREVIEW_TIMER_INITIAL` for the countdown reload after a preview
    sound starts.
  - Added `BGM_PREVIEW_UNUSED_PERIOD_OPTION0..2` for the write-only
    BGM-specific values stored in `BGM_PREVIEW_UNUSED_PERIOD`.
  - Added explicit `OPTION_BGM_VALUE_1` / `OPTION_BGM_VALUE_2` constants and
    reused `OPTION_BGM_OFF_VALUE` in the marker/preview selection paths.
  - Replaced the default `BGM_INDEX` raw `$34` store with `SND_BGM_OPTION0`.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted BGM preview scans show the new reset, timer reload, write-only
    period, and BGM option value constants in the touched paths, with no raw
    `$1B/$2A/$0C/$01/$02/$34` preview/default-BGM immediates left there.
  - Targeted constant scan shows the new names in `Yoshi/constants.inc`,
    `Yoshi/bank_000.asm`, and matching docs.
  - `git diff --check` passed.

### Phase 4: 1P Preplay Background Layout Constants
- **Status:** completed
- Actions taken:
  - Added named constants for the 1P pre-play full-screen background fill,
    game-type panel, level panel, speed panel, BGM panel, background tile, and
    panel-clear tile.
  - Replaced the raw coordinate, rectangle-size, and tile immediates in
    `Draw1PPreplayBackground`.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `Draw1PPreplayBackground` scan shows the new
    `PREPLAY_1P_*` constants in the touched path, with no raw
    `$0000/$1412/$cf/$0301/$1202/$0601/$1204/$0b01/$0e01/$4a`
    background-layout immediates left there.
  - `git diff --check` passed.

### Phase 4: 2P Preplay Background Layout Constants
- **Status:** completed
- Actions taken:
  - Added named constants for the 2P pre-play full-screen background fill,
    upper setup panel, lower setup panel, background tile, and panel-clear
    tile.
  - Replaced the raw coordinate, rectangle-size, and tile immediates in
    `Draw2PPreplayBackground`.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `Draw2PPreplayBackground` scan shows the new
    `PREPLAY_2P_*` constants in the touched path, with no raw
    `$0000/$1412/$d0/$0301/$1206/$0b01/$4a` background-layout immediates left
    there.
  - `git diff --check` passed.

### Phase 4: 1P Preplay Label And Text Layout Constants
- **Status:** completed
- Actions taken:
  - Added named constants for the 1P pre-play game-type, level, speed, and BGM
    label/text coordinates.
  - Added shared pre-play level/speed label tile-row constants and reused them
    in both 1P and 2P setup label drawing paths.
  - Added 1P-specific game-type and BGM label tile-row constants, including
    selected-row variants.
  - Updated option-variable, link-state, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted 1P pre-play label/text scan shows the new `PREPLAY_*` constants
    in the touched paths, with no raw
    `$0B07/$0602/$04AA/$04A6/$0E02/$03B9/$03B6/$0B02/$04B2/$04AE/$0302/$04A2/$049E/$0307/$0F10/$0F06`
    layout immediates left there.
  - Targeted 2P level/speed label scan shows the shared tile-row constants in
    the touched paths.
  - `git diff --check` passed.

### Phase 4: 2P Preplay Role And Setting Layout Constants
- **Status:** completed
- Actions taken:
  - Added named constants for the 2P pre-play role header, top/bottom role
    panel coordinates, master/slave role-panel tile bases, and role-panel row
    delta.
  - Added named constants for the 2P local/peer level preview coordinates and
    local/peer speed text coordinates.
  - Replaced the corresponding raw layout and tile immediates in
    `Draw2PPreplayRoleHeader`, `Draw2PPreplaySpeedText`,
    `Draw2PPreplayRolePanels`, `Draw2PPreplayRolePanelAtCoord`,
    `Draw2PPreplayLevelLabel`, `Draw2PPreplaySpeedLabel`, and
    `Draw2PPreplayLevelText`.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted 2P pre-play layout scan shows the new `PREPLAY_2P_*` and shared
    label-row constants in the touched paths, with no raw
    `$0103/$0708/$0F08/$C3/$C9/$0402/$0C02/$0013/$0302/$0702/$0C`
    layout immediates left there.
  - `git diff --check` passed.

### Phase 3/4: Preplay Direction Input Bit Constants
- **Status:** completed
- Actions taken:
  - Replaced raw `bit 6/7/4/5` direction-key tests in the detached pre-play,
    live 1P pre-play, and live 2P pre-play non-Start input dispatchers with
    `PADB_UP`, `PADB_DOWN`, `PADB_RIGHT`, and `PADB_LEFT`.
  - Updated option-variable, link-state, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted detached/1P/2P pre-play input scan shows the new `PADB_*`
    direction constants in the touched dispatch paths, with no raw
    `bit 6/7/4/5` direction tests left there.
  - `git diff --check` passed.

### Phase 4: Detached Preplay Label Tile Row Constants
- **Status:** completed
- Actions taken:
  - Replaced the raw `$04AA/$04A6` tile rows in the detached label-tile tail
    after `BgmMarkerNoneText` with the shared
    `PREPLAY_LEVEL_LABEL_TILE_ROW` and
    `PREPLAY_LEVEL_LABEL_SELECTED_TILE_ROW` constants.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted detached label-tail scan shows the shared pre-play level-label
    constants in the touched path, with no raw `$04AA/$04A6` left there.
  - `git diff --check` passed.

### Phase 4: 1P BGM Marker String Tile Constants
- **Status:** completed
- Actions taken:
  - Replaced the raw `$9A/$4A` selected/blank tiles in `BgmMarker0Text` through
    `BgmMarkerNoneText` with `OPTION_MARKER_SELECTED_TILE` and
    `OPTION_MARKER_BLANK_TILE`.
  - Split the marker string rows for readability while preserving the exact
    byte sequence.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted BGM marker string scan shows the option marker tile constants in
    the touched strings, with no raw `$9A/$4A` marker tiles left there.
  - `git diff --check` passed.

### Phase 3/4: Settings Cursor Frame High-Bit Clear Helper
- **Status:** completed
- Actions taken:
  - Renamed the misleading `DrawCountdownNum` helper to
    `ClearSettingsCursorFrameHighBits`.
  - Renamed its loop to `ClearSettingsCursorFrameHighBitsLoop`.
  - Added `SETTINGS_CURSOR_OBJECT_COUNT` and
    `SETTINGS_CURSOR_FRAME_LOW_MASK` for the three settings cursor objects and
    the low-nibble frame mask.
  - Synced `Yoshi/yoshi.sym` and moved the note out of countdown-buffer docs
    into sprite/OAM docs.
  - Updated findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted old-name scan shows no old helper or loop name in source/symbols;
    only explanatory "former name" docs mention the old helper.
  - Targeted helper scan shows the new object count and frame-mask constants,
    with no raw `$03/$0F` values left in the helper.
  - `git diff --check` passed.

### Phase 4: Settings Cursor Sprite Init Records
- **Status:** completed
- Actions taken:
  - Added `SETTINGS_CURSOR_INIT_COPY_SIZE` for the 7-byte records copied by
    `ApplySettings` into sprite object slots 9-11.
  - Added settings cursor init constants for the unused byte, unused/grid-column
    byte, shared base Y, three frame/toggled-frame values, and three base-X
    positions.
  - Replaced the raw copy size and raw record values in
    `SettingsCursorSpriteInit0..2`.
  - Updated sprite/OAM, data-range, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ApplySettings` and `SettingsCursorSpriteInit0..2` scan shows the
    new `SETTINGS_CURSOR_*` constants, with no raw
    `$0007/$73/$30/$48/$60` values left in the touched path.
  - `git diff --check` passed.

### Phase 4: Option Marker Coordinate Table Constants
- **Status:** completed
- Actions taken:
  - Replaced the raw row/column bytes in `OptionMarkerPositions` with
    `HIGH()` / `LOW()` expressions over the existing `OPTION_MARKER_*_COORD`
    constants.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `OptionMarkerPositions` scan shows the marker coordinate constants
    via `HIGH()` / `LOW()`, with no raw row/column coordinate bytes left in the
    table.
  - `git diff --check` passed.

### Phase 4: Option Cursor Triplet Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `SettingsCursorTileData` to `OptionCursorInactiveTileTriplets`.
  - Renamed `SettingsCursorTileData0..2` to
    `OptionCursorLevelHighlightTileTriplets`,
    `OptionCursorSpeedHighlightTileTriplets`, and
    `OptionCursorBgmHighlightTileTriplets`.
  - Updated option-variable, data-range, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted old-name scan shows no `SettingsCursorTileData*` labels in source
    or recovery docs.
  - Targeted new-name scan shows the four `OptionCursor*TileTriplets` labels
    in source and matching docs.
  - `git diff --check` passed.

### Phase 4: Option Box Offset And Value Constant Cleanup
- **Status:** completed
- Actions taken:
  - Added `OPTION_BOX_NEUTRAL_TILE_OFFSET` and
    `OPTION_BOX_SELECTED_TILE_OFFSET` for the option box frame tile offsets
    passed through register `d` to the `DrawOptionBoxAtCoord`-based box
    helpers.
  - Added `OPTION_LEVEL_VALUE_1..3` for the level value comparisons in
    `DrawOptionValues`; level 0 still uses `and a`, and level 4 remains the
    fallthrough case after the table-bound `OPTION_LEVEL_OPTION_COUNT`.
  - Reused `MENU_CURSOR_ROW_LEVEL`, `MENU_CURSOR_ROW_SPEED`, and
    `MENU_CURSOR_ROW_BGM` in `UpdateCursorDisplay`.
  - Reused `OPTION_BGM_VALUE_1` and `OPTION_BGM_VALUE_2` in the option marker
    redraw path.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted option redraw scans found no remaining raw `ld d, $00/$06` or
    `cp $01/$02/$03` in the touched `UpdateCursorDisplay` /
    `DrawOptionValues` block, and no raw BGM `$01/$02` comparisons in the
    touched marker redraw block.
  - `git diff --check` passed.

### Phase 4: Option Box Helper Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the neutral option box layout helper from `DrawLabel` to
    `DrawOptionBoxLayout`.
  - Renamed the neutral level-value box redraw helper from `SetPalette` to
    `DrawOptionLevelValueBoxes`.
  - Renamed `UpdateBGMap` to `DrawOptionBoxAtCoord` and
    `TileDataLookup0` to `FillOptionBoxHorizontalRun`.
  - Renamed `TileDataLookup1..D` to individual option box helpers for the
    game-type, level panel/label/value boxes, speed panel/label, and BGM
    panel/label.
  - Synced `Yoshi/yoshi.sym`, option-variable notes, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no `DrawLabel`, `SetPalette`,
    `UpdateBGMap`, or `TileDataLookup*` labels/references in Bank 0/1 source
    or `Yoshi/yoshi.sym`.
  - `git diff --check` passed.

### Phase 4: Option Box Geometry And Frame Tile Cleanup
- **Status:** completed
- Actions taken:
  - Added `OPTION_DECORATION_START_COORD`,
    `OPTION_DECORATION_FIRST_TILE`, `OPTION_DECORATION_COUNT`, and
    `OPTION_DECORATION_COLUMN_STEP` for the five-tile decoration strip in
    `DrawOptionTextLabels`.
  - Added `OPTION_BOX_TOP_LEFT_TILE_BASE` through
    `OPTION_BOX_BOTTOM_RIGHT_TILE_BASE` for the shared option box frame
    renderer.
  - Added `OPTION_BOX_*_COORD` constants for the game-type, level, speed, and
    BGM option boxes.
  - Added `OPTION_BOX_*_INNER_SIZE` constants for the inner row/width values
    passed in `bc` to `DrawOptionBoxAtCoord`, plus
    `OPTION_BOX_INNER_WIDTH_HIGH` for the zero high byte used when skipping the
    interior side-row width.
  - Updated option-variable, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted scans over `DrawOptionTextLabels` through the option box helper
    block found no remaining raw numeric literals.
  - `git diff --check` passed.

### Phase 5: Board Draw And Drop Stride Constant Cleanup
- **Status:** completed
- Actions taken:
  - Added `BOARD_DRAW_FIRST_COLUMN` and
    `COLUMN_SPRITE_TOP_ROW_OFFSET`.
  - Replaced repeated manual `inc`/`dec` sequences in `DrawColumnSprite`,
    `ClearColumnRight`, `DrawAllColumns`, and the drop-cascade loops with
    `REPT` blocks over the existing geometry constants:
    `COLUMN_SPRITE_TOP_ROW_OFFSET`, `GRID_PIECE_TILE_WIDTH`,
    `BOARD_CELL_STRIDE`, and `DROP_ANIM_STATE_STRIDE`.
  - Updated board-layout, drop-animation, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted scans confirmed the new board/drop stride constants are present in
    source and recovery docs.
  - `git diff --check` passed.

### Phase 5: Landing And Scan Row-Step Constant Cleanup
- **Status:** completed
- Actions taken:
  - Added `LEVEL_FALL_DELAY_TABLE_COUNT` and
    `LEVEL_FALL_DELAY_MAX_INDEX` for the `GetLevelFallDelay` table clamp.
  - Added `BOARD_SCAN_STEP_INITIAL` and `BOARD_SCAN_BG_REFRESH_ROW` for the
    board-scan animation loop seed and BG refresh row.
  - Added `UNRESOLVED_LANDING_RESET_TIMER_INITIAL` for the reset-time seed
    written by `ClearRoundLandingAndResultState`.
  - Added `FIELD_COLUMN_EFFECT_FRAME_COMMIT` and
    `FIELD_COLUMN_EFFECT_FRAME_LAND` for the two `SpawnFieldColumnEffect`
    call-site frame arguments.
  - Reused `BOARD_CELL_STRIDE` for direct landing, staged payload backstep,
    initial-board rotate lookahead/backtrack, landing counter decrement,
    commit top-row advance, and board-scan cleanup/search stepping.
  - Updated board-layout, fall-timing, field-animation, sprite-OAM, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-literal scans found no old raw `$14/$13`, `$00/$03`, or
    field-column `$00/$01` literals in the touched fall-delay, board-scan,
    commit, and landing blocks.
  - Targeted new-name scan confirmed the new constants are present in source
    and recovery docs.
  - `git diff --check` passed.

### Phase 4: Player Cursor And Round-Complete Sprite Record Labels
- **Status:** completed
- Actions taken:
  - Renamed the player cursor frame tile lists from address-only
    `SpriteTileList_420e..4220` labels to
    `SpriteTileList_PlayerCursorFrame0..4`.
  - Renamed the player cursor layouts from `SpriteLayout_42cb`,
    `SpriteLayout_42dd`, and `SpriteLayout_42e9` to
    `SpriteLayout_PlayerCursorSixTile`,
    `SpriteLayout_PlayerCursorFourTileForward`, and
    `SpriteLayout_PlayerCursorFourTileFlipped`.
  - Renamed the round-complete tile list and four flip-specific layouts from
    `SpriteTileList_4226` / `SpriteLayout_4227..4230` to
    `SpriteTileList_RoundCompleteTile` and
    `SpriteLayout_RoundCompleteTile*`.
  - Updated sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no old player-cursor or round-complete
    address-only sprite labels in `Yoshi/bank_001.asm`; the only old names left
    are historical references in this progress entry.
  - Targeted new-label scan confirmed the player cursor and round-complete
    sprite labels are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4: Settings Cursor And Round-Transition Sprite Record Labels
- **Status:** completed
- Actions taken:
  - Renamed settings cursor frame tile lists from address-only
    `SpriteTileList_4233..423d` labels to
    `SpriteTileList_SettingsCursorFrame*` labels, including the alternate
    frame values selected through the BGM cursor frame toggle path.
  - Renamed shared `SpriteLayout_42bf` to `SpriteLayout_TwoTileRow`; the
    overlapping `SpriteTileList_42bf` label remains for the game-over piece
    table because that exact address is also used as a tile list.
  - Renamed round-transition frame tile lists from address-only
    `SpriteTileList_423f..4263` labels to
    `SpriteTileList_RoundTransitionFrame*` labels.
  - Renamed round-transition layouts from `SpriteLayout_426b..428f` to
    two/four/six/eight-sprite layout names.
  - Updated sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no old settings-cursor or
    round-transition address-only sprite labels in source or active recovery
    docs.
  - Targeted new-label scan confirmed the settings cursor and round-transition
    sprite labels are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4: Game-Over Sprite Record Labels
- **Status:** completed
- Actions taken:
  - Renamed the remaining game-over / piece-display sprite tile lists from
    address-only `SpriteTileList_42a7..42bf` labels to
    `SpriteTileList_PieceDisplayFrame*` labels.
  - Renamed `SpriteLayout_42c5` to
    `SpriteLayout_PieceDisplayTwoTileRow`.
  - Kept the intentional overlap where
    `SpriteTileList_PieceDisplayFrame22` shares the same address as the
    generic `SpriteLayout_TwoTileRow`.
  - Updated sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no address-only `SpriteTileList_42xx` or
    `SpriteLayout_42xx` labels in `Yoshi/bank_001.asm` or active recovery
    docs.
  - Targeted new-label scan confirmed the game-over / piece-display sprite
    labels are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4: 2P Pre-Play Init Sound ID Classification
- **Status:** completed
- Actions taken:
  - Added `SND_2P_PREPLAY_MASTER_INIT` for sound ID `$6B` and
    `SND_2P_PREPLAY_SLAVE_INIT` for sound ID `$6D`.
  - Replaced the raw `cp $02`, `ld a, $6b`, and `ld a, $6d` in
    `InitTwoPlayerPreplayScreen` with `LINK_ROLE_SLAVE` and the new sound ID
    constants.
  - Added sound-index aliases
    `SoundIndexEntry_TwoPlayerPreplayMasterInit` and
    `SoundIndexEntry_TwoPlayerPreplaySlaveInit`.
  - Updated sound-engine, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted immediate-before-`PlaySound` scan found no remaining raw
    `ld a, $NN` sound IDs before direct `PlaySound` calls.
  - Targeted `InitTwoPlayerPreplayScreen` scan found no raw `cp $02`,
    `ld a, $6b`, or `ld a, $6d`.
  - Targeted new-name scan confirmed the 2P pre-play sound constants and
    sound-index aliases are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4: Countdown Tile Slot And Playfield Digit Constants
- **Status:** completed
- Actions taken:
  - Added `COUNTDOWN_TILE_SLOT_A_TYPE_COORD` and
    `COUNTDOWN_TILE_SLOT_B_TYPE_COORD` for the A/B-type countdown tilemap
    origins in `Draw1PCountdownDigitTileSlots`.
  - Added `COUNTDOWN_TILE_SLOT_0..3` for the four alternating countdown tile
    IDs written into the 1P playfield tilemap.
  - Added `COUNTDOWN_BLIT_TIMER_RELOAD` for the pending countdown VRAM blit
    timer seed.
  - Added `PLAYFIELD_DIGIT_MASK`, `PLAYFIELD_DIGIT_TILE_BASE`,
    `PLAYFIELD_BLANK_DIGIT_TILE`, and
    `PLAYFIELD_ROUND_TIMER_SEPARATOR_TILE`; reused them in
    `UnusedDrawLowNibbleTileDigitsByCoord`,
    `UnusedDrawTwoDigitBcdTilePair`,
    `DrawLevelDisplayDigits`, and `DrawRoundTimerDigits`.
  - Updated countdown-buffer, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted countdown/digit stale-literal scans found no old raw countdown
    coordinates, tile IDs, timer reload, playfield digit base, blank digit
    tile, or round-timer separator in the touched blocks.
  - Targeted new-name scan confirmed the countdown and playfield digit
    constants are present in source and recovery docs.
  - Targeted immediate-before-`PlaySound` scan still found no remaining raw
    `ld a, $NN` sound IDs before direct `PlaySound` calls.
  - `git diff --check` passed.

### Phase 5: Score BCD Cap And Clear Span Constants
- **Status:** completed
- Actions taken:
  - Added `SCORE_DISPLAY_DIGIT_COUNT` for the five unpacked display digits
    written by `AddScore`.
  - Added `SCORE_CLEAR_BYTE_COUNT` for the `InitGameScreen` clear span from
    `SCORE_BCD_LOW` through the display digits; the preserved unused byte is
    saved before the clear and restored afterward.
  - Added `SCORE_BCD_HIGH_ADDEND`, `SCORE_BCD_HIGH_OVERFLOW_LIMIT`,
    `SCORE_BCD_LOW_MID_MAX`, and `SCORE_BCD_HIGH_MAX` for the packed-BCD
    overflow path that saturates the score at `99999`.
  - Updated memory-map, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted score stale-literal scan found no raw `adc $00`, `cp $10`,
    `$99/$09` saturation loads, or `ld b, $09` clear count in the touched
    `AddScore` / `InitGameScreen` block.
  - Targeted new-name scan confirmed the score constants are present in source
    and recovery docs.
  - `git diff --check` passed.

### Phase 4: Game BG And Field-Column Pattern Constants
- **Status:** completed
- Actions taken:
  - Added `GAMEPLAY_BG_TOP_ROW_COORD`,
    `GAMEPLAY_BG_TOP_ROW_WIDTH`, and `GAMEPLAY_BG_TOP_ROW_TILE` for the
    `DrawGameplayBgTopRowIfNoResultFlow` top-row fill.
  - Added `FIELD_COLUMN_TILE_PATTERN_RECORD_SIZE`,
    `FIELD_COLUMN_TILE_PATTERN_RECORD_COUNT`,
    `FIELD_COLUMN_TILE_PATTERN_INDEX_SHIFT`, and
    `FIELD_COLUMN_TILE_PATTERN_DEST_COORD` for the `DrawFieldColumnTilePattern`
    copy path.
  - Added `ACTIVE_LEVEL_MAX` and reused it in the single-player
    `StartNextRound` level increment clamp.
  - Corrected recovery docs that described `FieldColumnTilePatternTable` as
    six records; the actual `01:$442C-$445B` range is three 16-byte records.
  - Updated data-range, memory-map, column-state, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted Bank 1 game-BG / field-column stale-literal scan found no raw
    top-row width/coord/tile, field-column destination/copy size, or
    next-round active-level max literal in the touched block.
  - Targeted new-name scan confirmed the game-BG and field-column pattern
    constants are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 3/4/5: Title Input And Egg Display Constants
- **Status:** completed
- Actions taken:
  - Added title label-row marker constants for the two row-15/16 marker
    coordinates and clear/selected tile IDs.
  - Added title marker blink duration constants, title player-mode
    count/toggle constants, and title link start/ready handshake byte
    constants.
  - Replaced the title input raw `bit 7/6/2` tests with `PADB_DOWN`,
    `PADB_UP`, and `PADB_SELECT`.
  - Added `LEVEL_DISPLAY_DIGIT_LIMIT` / `LEVEL_DISPLAY_MAX_DIGIT` for the
    level-display decimal rollover and saturation checks.
  - Added explicit A/B-type egg count coordinates and reused the existing
    A/B-type egg text display coordinates in `DrawEggTextFrameByIndex`.
  - Updated title-menu, egg-counter, board-layout, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted title-input stale-literal scan found no raw Up/Down/Select bit
    tests, title label marker coordinates/tiles, title link handshake bytes,
    marker blink durations, or title player-mode toggle/count immediates in
    the touched title input block.
  - Targeted level/egg stale-literal scans found no raw level-display
    `$09/$0A` bounds or raw A/B-type egg display/count packed coordinates in
    the touched blocks.
  - Targeted new-name scan confirmed the title input/marker/link,
    level-display, and egg display constants are present in source and
    recovery docs.
  - `git diff --check` passed.

### Phase 4/5: Player Cursor Init Constants
- **Status:** completed
- Actions taken:
  - Added `FIELD_COLUMN_TILE_PATTERN_INITIAL_INDEX` for the slot-0 cursor's
    starting field-column pattern selection.
  - Added `PLAYER_CURSOR_INITIAL_FRAME`,
    `PLAYER_CURSOR_INITIAL_BASE_Y`, and `PLAYER_CURSOR_INITIAL_BASE_X` for
    the `InitPlayerCursorObject` sprite object seed values.
  - Replaced the shared `FillTilemapRectByCoord` row-advance literal with
    `BG_MAP_ROW_STRIDE`.
  - Updated sprite/OAM, column-state, board-layout, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted player-cursor stale-literal scan found no raw initial field-pattern
    index, frame, base Y, or base X immediates in `InitPlayerCursorObject`.
  - Targeted tilemap-rect stale-literal scan found no raw `$14` row stride in
    `FillTilemapRectByCoord`.
  - Targeted new-name scan confirmed the player-cursor init constants and
    `BG_MAP_ROW_STRIDE` use are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4/5: Egg Text Animation Constants And Unused Inline Drawer
- **Status:** completed
- Actions taken:
  - Added `EGG_TEXT_FRAME_0..2`,
    `EGG_TEXT_FRAME_TOGGLE_MASK`,
    `EGG_TEXT_ALT_ANIM_ACTIVE_VALUE`, and
    `EGG_TEXT_ALT_PHASE_TOGGLE_MASK`.
  - Reused the frame constants in `DrawEggTextFrameByIndex`,
    `UpdateEggTextAnimation`, `ToggleEggTextAltAnimation`, and
    `EnableEggTextAltAnimation`.
  - Labeled the unreferenced `01:$45C6-$45EF` inline egg-text tile writer as
    `UnusedInlineEggTextFrame0Drawer` in source and `Yoshi/yoshi.sym`.
  - Updated egg-counter, data-range, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted egg-text frame stale-literal scans found no raw `cp $01`,
    `ld a, $01`, `ld a, $02`, `xor $03`, or `xor $01` in the touched
    `DrawEggTextFrameByIndex` / egg-text animation blocks.
  - Targeted new-name scan confirmed `UnusedInlineEggTextFrame0Drawer` and the
    egg-text frame/toggle constants are present in source, `Yoshi/yoshi.sym`,
    and recovery docs.
  - `git diff --check` passed.

### Phase 4: UpdateSprites Redraw And Frame Sentinels
- **Status:** completed
- Actions taken:
  - Added `LCD_REDRAW_HIDE_ALL_REQUEST`,
    `LCD_REDRAW_EXPAND_REQUEST`, and
    `LCD_REDRAW_HIDE_ALL_SENTINEL` for the `UpdateSprites` redraw gate.
  - Added `SPRITE_OBJECT_FRAME_DISABLED` for sprite object frame `$FF`
    skip behavior.
  - Replaced the two raw `$FF` checks in the `UpdateSprites` redraw gate and
    frame-dispatch path.
  - Updated sprite/OAM, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `UpdateSprites` stale-literal scan found no raw `cp $ff` in the
    touched redraw/frame-dispatch block.
  - Targeted new-name scan confirmed the redraw and disabled-frame constants
    are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4: ClearSpriteObjectBuffer Byte Count
- **Status:** completed
- Actions taken:
  - Added `SPRITE_OBJECT_BUFFER_CLEAR_BYTES` for the `$FF` byte span cleared
    by `ClearSpriteObjectBuffer`.
  - Replaced the raw `ld b, $ff` in `ClearSpriteObjectBuffer`.
  - Updated sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ClearSpriteObjectBuffer` stale-literal scan found no raw
    `ld b, $ff` in the touched block.
  - Targeted new-name scan confirmed `SPRITE_OBJECT_BUFFER_CLEAR_BYTES` is
    present in source and recovery docs.
  - `git diff --check` passed.

### Phase 3/4/5: Title Player Mode Underflow Sentinel
- **Status:** completed
- Actions taken:
  - Added `TITLE_PLAYER_MODE_UNDERFLOW_SENTINEL` for the post-decrement `$FF`
    rejection in `SelectTitleOnePlayerMode`.
  - Replaced the raw `cp $ff` in the title 1P selection path.
  - Updated title-menu, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ProcessTitleInput` stale-literal scan found no raw `cp $ff`.
  - Targeted new-name scan confirmed `TITLE_PLAYER_MODE_UNDERFLOW_SENTINEL`
    is present in source and recovery docs.
  - `git diff --check` passed.

### Phase 4: Sound Reset Default Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_COUNTER_INIT_VALUE` for the `$01` seed shared by loop counters,
    note lengths, length scales, and tempo high bytes in the reset/setup paths.
  - Added `SOUND_OUTPUT_MASK_ALL` for the reset `$FF` output mask.
  - Added `SOUND_NR50_RESET_VALUE` for the repeated `$77` `rNR50` restore/init
    value.
  - Replaced only the reset/setup uses in `SoundEngine`,
    `ClearSoundChannelStateForNewEntry`, `StopAllSoundHW`, and
    `StartSoundSequence`; unrelated `$01/$FF` literals in `WaitVBlank` and
    `HandleWaveUpdate` remain raw because they have different meanings.
  - Updated sound-engine, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted sound reset/setup stale-literal scan found no raw
    `ld a, $01`, `ld a, $ff`, or `ld a, $77` in the touched reset/setup range.
  - Targeted new-name scan confirmed the three sound reset constants are present
    in source and recovery docs.
  - `git diff --check` passed.

### Phase 5: Gameplay Update Top-Level Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the misleading `DrawBox` top-level gameplay hub to
    `UpdateGameplayObjectSlotsAndRoundState`.
  - Renamed `DisplayScore` to `UpdatePieceFallTimer`,
    `DisplayLevel` to `UpdatePieceDisplayByGameType`,
    `DisplayLines` to `CheckGameplayObjectSlotsActive`, and
    `DisplaySpeed` to `UpdateFallAcceleration`.
  - Updated `Yoshi/yoshi.sym` and recovery docs that referenced the old display
    names.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-name scan found no remaining `DrawBox`, `DisplayScore`,
    `DisplayLevel`, `DisplayLines`, or `DisplaySpeed` references outside this
    progress log entry.
  - `git diff --check` passed.

### Phase 5: Gameplay Active Slot Count Constant
- **Status:** completed
- Actions taken:
  - Replaced the raw `ld b, $04` in
    `UpdateGameplayObjectSlotsAndRoundState` with
    `SPRITE_OBJECT_ACTIVE_SLOT_COUNT`.
  - Updated sprite/OAM, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-literal scan found no raw `ld b, $04` in the touched
    gameplay update hub.
  - Targeted new-name scan confirmed `SPRITE_OBJECT_ACTIVE_SLOT_COUNT` is used
    by the hub and documented in recovery notes.
  - `git diff --check` passed.

### Phase 4: LCD Redraw Expand Request Call Sites
- **Status:** completed
- Actions taken:
  - Replaced raw `ld a, $01` writes to `LCD_REDRAW` with
    `LCD_REDRAW_EXPAND_REQUEST` in title setup, playfield setup, unpause, and
    game-tile reload paths.
  - Left hide-all request paths as `xor a` because replacing them with
    `ld a, LCD_REDRAW_HIDE_ALL_REQUEST` would change instruction size.
  - Updated sprite/OAM, memory-map, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-literal scan found no raw `ld a, $01` followed by
    `ld [LCD_REDRAW], a`.
  - Targeted new-name scan confirmed `LCD_REDRAW_EXPAND_REQUEST` is used at the
    call sites and documented in recovery notes.
  - `git diff --check` passed.

### Phase 5: Drop Cursor Active And Fall Timer Hold Values
- **Status:** completed
- Actions taken:
  - Added `DROP_CURSOR_ANIM_ACTIVE_VALUE` for the value stored when
    `HandlePlayfieldInput` accepts an A/B drop input.
  - Added `PIECE_FALL_TIMER_ANIM_HOLD_RELOAD` for the one-frame fall-timer hold
    applied while drop/cursor animation is active.
  - Replaced the two raw `$01` loads in `UpdatePieceFallTimer` and
    `HandlePlayfieldInput`.
  - Updated column-state, fall-timing, memory-map, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-literal scan found no raw `ld a, $01` in the touched
    `UpdatePieceFallTimer` / `HandlePlayfieldInput` range.
  - Targeted new-name scan confirmed both new constants are present in source and
    recovery docs.
  - `git diff --check` passed.

### Phase 5: Fall Acceleration Level Boundary Constants
- **Status:** completed
- Actions taken:
  - Added `PIECE_FALL_ACCEL_LEVEL3_VALUE` for the level-3 branch comparison
    used by both `UpdateFallAcceleration` and `InitBTypeFallTimingAndBoardSeed`.
  - Added `PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD` for the high-level branch
    threshold shared by the same two paths.
  - Replaced the raw `cp $03` / `cp $04` comparisons in the fall-acceleration
    update and B-type setup branches.
  - Updated fall-timing, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after correcting the constant definition
    order issue recorded below.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-literal scan found no raw `cp $03` / `cp $04` in the touched
    fall-acceleration update/setup ranges.
  - Targeted new-name scan confirmed the new fall-acceleration boundary constants
    are present in source and recovery docs.
  - `git diff --check` passed.

### Phase 3/5: Pause And Link-Send Active Flag Values
- **Status:** completed
- Actions taken:
  - Added `PAUSE_FLAG_ACTIVE`, `SOUND_PAUSE_FLAG_ACTIVE`, and
    `LINK_SEND_DROP_INPUT_LOCK_ACTIVE` for the `$01` values stored by the
    pause, sound-pause, and link-send wait paths.
  - Replaced the raw active-value loads in `PauseGame`, `Send2PData`, and
    `HandleReceivedLinkPausePacket`.
  - Kept the clear paths as `xor a` to preserve the existing instruction
    shape.
  - Updated link-state, sound-engine, memory-map, architecture, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted touched-range scan shows the new active flag constants at the
    pause, link-send, and received link-pause stores.
  - Targeted new-name scan confirmed all three constants are present in source
    and recovery docs.
  - `git diff --check` passed.

### Phase 5: Game-Turn Table Index Boundary Constants
- **Status:** completed
- Actions taken:
  - Added `GAME_TURN_TABLE_INDEX_SENTINEL` for the no-increment `$FF` table
    index value used by `AdvanceGameTurnTableIndex`.
  - Added `GAME_TURN_TABLE_LOOP_END_INDEX` and
    `GAME_TURN_TABLE_LOOP_RESTART_INDEX` for the observed `$D1 -> $C8`
    wraparound in the game-turn schedule.
  - Replaced the raw comparisons/stores in `AdvanceGameTurnTableIndex`.
  - Renamed the internal exact-address table landmark from
    `GameTurnParamTable_0c40` to `GameTurnParamTableContinuation`.
  - Updated data-range, memory-map, fall-timing, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted touched-range scan shows the new game-turn table boundary
    constants in `AdvanceGameTurnTableIndex`.
  - Targeted new-name scan confirmed the constants and continuation label are
    present in source and recovery docs, with no stale
    `GameTurnParamTable_0c40` reference.
  - `git diff --check` passed.

### Phase 5: Piece-Display Object Builder Naming
- **Status:** completed
- Actions taken:
  - Renamed the misleading game-over-specific object type constant to
    `SPRITE_OBJECT_TYPE_PIECE_DISPLAY`, matching its use by both the
    display-results and game-over paths.
  - Renamed the Bank 0 piece-display object builder entry points and locals:
    `BuildPieceDisplayObjects`, `BuildPieceDisplayObjectsFromStates`,
    `InitPieceDisplayObjectFromState`, `InitActivePieceDisplayObject`,
    `BuildGameOverPieceDisplayObjects`,
    `BuildGameOverPieceDisplayObjectSlotsLoop`, and
    `AdvanceGameOverPieceDisplaySlot`.
  - Synced the symbol file labels for the same addresses.
  - Updated piece-display, sprite/OAM, memory-map, data-range, board-layout,
    fall-timing, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-name scan found no remaining old game-over-specific object
    builder names in source or recovery docs.
  - `git diff --check` passed.

### Phase 5: Piece-Display Object Slot Mechanics Constants
- **Status:** completed
- Actions taken:
  - Added `PIECE_DISPLAY_OBJECT_CLEAR_SLOT_ADVANCE` for the `$000E` stride used
    by `ClearPieceDisplayObjectSlotsLoop` after clearing a slot's type/frame
    bytes.
  - Added `GAME_OVER_PIECE_DISPLAY_SLOT_OFFSET` for the offset that maps the
    four display-state entries onto sprite object slots 5-8.
  - Replaced the piece-display object initial phase raw `$01` with
    `SPRITE_OBJECT_PHASE_WAIT`.
  - Updated piece-display, sprite/OAM, findings, and task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted touched-range scan found no raw `$01`, `$04`, or `$000E` in the
    piece-display object builder/clear range.
  - `git diff --check` passed.

### Phase 5: Piece-Display Special-Selection Flag Values
- **Status:** completed
- Actions taken:
  - Added `PIECE_DISPLAY_STATE_EMPTY` for the display-state clear pass.
  - Added `PIECE_DISPLAY_FORCE_FLAG_ACTIVE` and
    `PIECE_DISPLAY_FORCE_FLAG_INACTIVE` for the timer-gated force paths and
    post-application clear.
  - Added `PIECE_DISPLAY_SKIP_SPECIAL_MIN_COUNT` and
    `PIECE_DISPLAY_SKIP_SPECIAL_ACTIVE` for the one-shot special-selection
    skip path in `DisplayResults`.
  - Updated piece-display, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted touched-range scan found no stale raw `$03`, `$01`, or `$00` in
    the updated piece-display special-selection / force-flag ranges.
  - `git diff --check` passed.

### Phase 5: B-Type Initial Board Seed Table Naming
- **Status:** completed
- Actions taken:
  - Renamed the B-type seed table label to `BTypeColumnTopRowSeedTable` because
    the setup path indexes it by `ACTIVE_LEVEL` and stores the result into
    `COLUMN_TOP_ROW_SEED`.
  - Added `B_TYPE_INITIAL_PIECE_DISPLAY_COUNT` for the B-type setup write to
    `PIECE_DISPLAY_COUNT`.
  - Added `INITIAL_BOARD_FILL_VBLANK_WAIT_FRAMES` for the
    `FillInitialBoardWithVBlankWait` delay stored in `VBLANK_BUSY`.
  - Updated board-layout, column-state, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-name and touched-range raw `$02` / `$0A` scans returned no
    matches in the source/recovery docs and updated setup ranges.
  - `git diff --check` passed.

### Phase 5: Drop-Up Boundary Clear Delta Constant
- **Status:** completed
- Actions taken:
  - Added `DROP_ANIM_UP_CLEAR_LEFT_MIN_DELTA` for the saved row-delta
    comparison shared by `HandleDropUpState3Boundary` and
    `HandleDropUpFinalBoundary`.
  - Replaced the two raw `cp $01` comparisons in those late drop-up boundary
    handlers.
  - Updated drop-animation, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted drop-up boundary scan found no remaining raw `cp $01` in the
    touched state-3/final boundary block.
  - `git diff --check` passed.

### Phase 5: 2P Round-Transition Prelude Constants
- **Status:** completed
- Actions taken:
  - Added `ROUND_TRANSITION_BASE_X_OFFSET` for slot 9's transition-object base
    X adjustment from `FALLING_PIECE_GRID_COLUMN`.
  - Added `ROUND_TRANSITION_PRE_FRAME_0` and
    `ROUND_TRANSITION_PRE_FRAME_1` for the two pre-loop frame writes before
    `SendRoundTransitionFrameLoop`.
  - Added `ROUND_TRANSITION_PRE_FRAME_SEND_FRAMES` for the two equal
    `Send2PData` waits in that prelude.
  - Updated sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted 2P round-transition prelude scan found no remaining raw
    `add $10`, frame `$00/$10`, or `ld b, $0F` immediates in the touched
    block.
  - `git diff --check` passed.

### Phase 5: Board-Scan Single-Step Distance Constant
- **Status:** completed
- Actions taken:
  - Added `BOARD_SCAN_SINGLE_STEP_DISTANCE` for the distance special case in
    `ScanBoard` after it derives and increments the scan distance.
  - Replaced the raw `cp $01` before `StoreBoardScanDistanceParam`.
  - Updated board-layout, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ScanBoard` distance block scan found no remaining raw `cp $01`.
  - `git diff --check` passed.

### Phase 5: Inactive Sprite Object Type Constant
- **Status:** completed
- Actions taken:
  - Added `SPRITE_OBJECT_TYPE_NONE` for logical sprite object type zero.
  - Replaced the round-transition reward tail's slot-9 type clear with
    `SPRITE_OBJECT_TYPE_NONE`.
  - Updated sprite/OAM, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted round-transition reward-tail scan found no remaining raw
    `ld [hl], $00` in the touched slot-9 type clear.
  - `git diff --check` passed.

### Phase 5: Drop Cursor Animation Inactive Value
- **Status:** completed
- Actions taken:
  - Added `DROP_CURSOR_ANIM_INACTIVE` for the zero value stored in
    `DROP_CURSOR_ANIM_ACTIVE`.
  - Replaced the raw `ld [hl], $00` initialization in `InitGameBoard`.
  - Updated column-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `InitGameBoard` scan found no remaining raw `ld [hl], $00` in the
    drop-cursor active flag initialization.
  - `git diff --check` passed.

### Phase 5: Piece-Display Forced-State Count Comparison
- **Status:** completed
- Actions taken:
  - Replaced the raw `cp $07` in `AnimateTitle` with
    `PIECE_DISPLAY_FORCED_STATE`.
  - Updated piece-display, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `AnimateTitle` scan found no remaining raw `cp $07` in the
    touched piece-display count block.
  - `git diff --check` passed.

### Phase 5: Piece-Display Slot-Order Initial Indices
- **Status:** completed
- Actions taken:
  - Added `PIECE_DISPLAY_SLOT_INDEX_0..3` for the four initial values written
    to `PIECE_DISPLAY_SLOT_ORDER`.
  - Replaced the raw `$00/$01/$02/$03` writes in
    `InitPieceDisplaySlotOrder`.
  - Updated piece-display, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `InitPieceDisplaySlotOrder` scan found no remaining raw
    `$00-$03` writes in the touched block.
  - `git diff --check` passed.

### Phase 4/5: Link Pending Field-Rise None Value
- **Status:** completed
- Actions taken:
  - Added `LINK_PENDING_FIELD_RISE_NONE` for the zero value stored when
    `ApplyPartialPendingFieldRise` consumes all pending field-rise payload.
  - Replaced the raw `ld [hl], $00` in the partial pending-field-rise path.
  - Updated link-state, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted `ApplyPartialPendingFieldRise` scan confirms the pending byte is
    cleared with `LINK_PENDING_FIELD_RISE_NONE`.
  - `git diff --check` passed.

### Phase 4/5: Result Flow Inactive And Round-End Wait High Byte
- **Status:** completed
- Actions taken:
  - Added `RESULT_FLOW_INACTIVE` for the zero value written when
    `ReturnRoundEndToTitle` clears `RESULT_FLOW_ACTIVE`.
  - Added `ROUND_END_WAIT_INITIAL_FRAMES_HI` for the high byte of the
    little-endian `$003C` `ROUND_END_WAIT_TIMER` seed in `EnterRoundEndState`.
  - Updated memory-map, result-record, state-machine, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted round-end scan confirms the two touched raw zero stores now use
    `RESULT_FLOW_INACTIVE` and `ROUND_END_WAIT_INITIAL_FRAMES_HI`.
  - `git diff --check` passed.

### Phase 4/5: Link Result Mark Screen Routine Rename
- **Status:** completed
- Actions taken:
  - Renamed the stale high-score-table routine to
    `UpdateLinkResultMarksAndScreen`.
  - Updated the single call site, `Yoshi/yoshi.sym`, link-state, memory-map,
    graphics-load, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no remaining old high-score-table label.
  - `git diff --check` passed.

### Phase 4/5: Link Result Confirm Helper Rename
- **Status:** completed
- Actions taken:
  - Renamed `DrawLinkResultRoleStatusStrip` for the helper that fills the
    result status strip according to `LINK_ROLE`.
  - Renamed `FillLinkResultWideScoreArea` and
    `FillLinkResultNarrowScoreArea` for the two observed score-area fill
    variants used by the link result confirm path.
  - Updated `Yoshi/yoshi.sym`, link-state, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no remaining old link-result helper names.
  - `git diff --check` passed.

### Phase 4/5: Bank 3 Link Result Graphics Label Rename
- **Status:** completed
- Actions taken:
  - Renamed the Bank 3 graphics ranges loaded by
    `UpdateLinkResultMarksAndScreen` / `BuildLinkResultScreen` from the older
    high-score/result wording to link-result screen labels:
    `Bank3LinkResultTilesTo9000`, `Bank3LinkResultTilesTo8800`,
    `Bank3LinkResultOverlayTilesTo9470`, and
    `Bank3LinkResultOverlayTilesTo8800`.
  - Renamed the matching destination/copy-size constants to
    `LINK_RESULT_OVERLAY_VRAM_DEST`,
    `BANK3_LINK_RESULT_TILE_BLOCK_COPY_SIZE`,
    `BANK3_LINK_RESULT_OVERLAY_9470_COPY_SIZE`, and
    `BANK3_LINK_RESULT_OVERLAY_8800_COPY_SIZE`.
  - Renamed the rendered tile-sheet evidence files and render preset entries
    for those four ranges from high-score wording to link-result wording.
  - Updated graphics-load, link-state, architecture, rendered-tile evidence,
    findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-name scan found no remaining legacy Bank 3 high-score
    symbol, constant, overlay, or mixed screen-role wording in the touched
    source and documentation set.
  - `git diff --check` passed.

### Phase 4/5: Link Result Confirm Wait Helper Rename
- **Status:** completed
- Actions taken:
  - Renamed the terminal zero-result menu wait helper to
    `WaitTerminalLinkResultMenuConfirm`.
  - Renamed the normal confirm-panel entry to
    `DrawLinkResultConfirmPanelsAndWait`.
  - Renamed the serial-confirm and tile-reload tail to
    `WaitLinkResultConfirmAndReloadTiles`, with local branches named for the
    master Start wait, peer confirm wait, and final game-tile reload.
  - Synced `Yoshi/yoshi.sym`, link-state notes, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no remaining old generic menu/sound/serial
    helper names in the touched source and documentation set.
  - `git diff --check` passed.

### Phase 4/5: Direct PlaySound ID Audit
- **Status:** completed
- Actions taken:
  - Updated sound-engine notes after the link-result helper rename so the
    `SND_CONFIRM`, `SND_LINK_RESULT_ZERO`, and
    `SND_LINK_RESULT_MENU_WAIT` evidence points to
    `DrawLinkResultConfirmPanelsAndWait` and
    `WaitTerminalLinkResultMenuConfirm`.
  - Recorded that direct `PlaySound` call-site evidence currently covers the
    named sound constants, while the remaining numeric `SoundIndexEntry_XX`
    labels still need sequence-internal or producer evidence before semantic
    aliases are added.
  - Updated findings, task-plan, and work-estimate notes.
- Test result:
  - `awk` scan for raw `ld a, $xx` immediately before `call PlaySound` in
    `Yoshi/bank_000.asm` / `Yoshi/bank_001.asm` returned no matches.
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Bank 3 Link Result Tile Evidence Refinement
- **Status:** completed
- Actions taken:
  - Inspected the rendered Bank 3 link-result tile sheets.
  - Refined `tools/render_gb_tiles.py`, the generated tile-sheet README, and
    graphics-load notes so `$5DD0` is documented as link-result
    name/text/number fragments and `$65D0` plus the terminal overlay ranges are
    documented as character, egg, and border fragments.
  - Updated findings, task-plan, and work-estimate notes.
- Test result:
  - `python3 tools/render_gb_tiles.py --preset yoshi-graphics` regenerated the
    18 evidence sheets and README successfully.
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted scan found no remaining legacy Bank 3 high-score evidence names.
  - `git diff --check` passed.

### Phase 4/5: Bank 2 Preplay And 2P Tile Range Rename
- **Status:** completed
- Actions taken:
  - Renamed the pre-play `$5800` overlay range to
    `PreplayMenuOverlayTiles`, matching its only load during
    `GAME_STATE_PREPLAY_INIT`.
  - Renamed the 2P `$71D0` range to `TwoPlayerSharedTiles`, matching the
    two-player load that runs for every `TWO_PLAYER_FLAG != 0` game tile load.
  - Renamed the 2P `$6F70` range to `TwoPlayerNonMasterTiles`, matching the
    load skipped for `LINK_ROLE_MASTER`.
  - Renamed the corresponding VRAM destination and copy-size constants, synced
    `Yoshi/yoshi.sym`, and regenerated the rendered tile-sheet evidence names.
  - Updated graphics-load, architecture, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `python3 tools/render_gb_tiles.py --preset yoshi-graphics` regenerated the
    18 evidence sheets and README successfully.
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-name scan found no remaining old Bank 2 extra/two-player
    numbered tile labels, constants, or rendered evidence names.
  - `git diff --check` passed.

### Phase 4/5: Bank 2 Unused Tail Tile Data
- **Status:** completed
- Actions taken:
  - Renamed the Bank 2 tail label at `02:$73D0` to
    `Bank2UnusedTailTileData`.
  - Added the tail range to `tools/render_gb_tiles.py`; regenerating the
    evidence sheets now emits `bank2_unused_tail_tile_data.png`.
  - Documented that confirmed Bank 2 graphics loads end before this range and
    that the rendered sheet is noise/padding-like rather than coherent UI or
    character art.
  - Synced `Yoshi/yoshi.sym`, architecture notes, graphics-load notes,
    data-range notes, findings, task-plan, and work-estimate notes.
- Test result:
  - `python3 tools/render_gb_tiles.py --preset yoshi-graphics` regenerated 19
    evidence sheets and README successfully.
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch scan returned no matches.
  - Generated `jr_000_*` label-definition scan returned no matches.
  - Anonymous relative `@+` / `@-` branch scan returned no matches.
  - Targeted stale-label scan found no remaining old Bank 2 unused tail label.
  - `git diff --check` passed.

### Phase 4/5: Link Confirm Symbol Boundary Sync
- **Status:** completed
- Actions taken:
  - Removed the stale `Yoshi/yoshi.sym` `00:33f7 .data:9` entry that still
    treated the recovered link-confirm wait entry as data.
  - Kept the existing `00:33f7 WaitLinkStartConfirm` and
    `00:33fa ContinueLinkConfirmWait` labels as the authoritative boundary for
    the Bank 0 link-confirm wait loop.
  - Synced findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted `Yoshi/yoshi.sym` stale-boundary scan found no remaining
    `00:33f7 .data` entry or stale `Data: Tilemap Data` section.
  - Additional `Yoshi/yoshi.sym` audit found no non-adjacent duplicate symbol
    addresses and no overlapping `.data` / `.text` / `.image` / `.code`
    blocks.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Bank 3 Graphics Symbol Sync
- **Status:** completed
- Actions taken:
  - Renamed the full Bank 3 graphics-data label from `TileGraphicsData2` to
    `Bank3GraphicsData`.
  - Added the existing Bank 3 load-site labels to `Yoshi/yoshi.sym` while
    keeping the full non-overlapping `03:4000 .data:4000` block directive.
    The `03:4000` symbol entry remains `Bank3MatchingTilesTo9000` rather than
    the source-only `Bank3GraphicsData` alias because `mgbdis.py` stores one
    label per bank/address.
  - Renamed the full Bank 3 rendered evidence sheet from
    `bank3_full_tile_graphics_data2` to `bank3_full_graphics_data`.
  - Synced graphics-load, architecture, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `python3 tools/render_gb_tiles.py --preset yoshi-graphics` regenerated 19
    evidence sheets and README successfully.
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted stale-name scan found no remaining `TileGraphicsData2` or
    `bank3_full_tile_graphics_data2` references in source, active docs,
    rendered manifest, or tile-render tooling.
  - `Yoshi/yoshi.sym` now contains the Bank 3 load-site labels at
    `$4000/$4800/$4E40/$5400/$5C00/$5DD0/$65D0/$6AB0/$6E40`.
  - Additional `Yoshi/yoshi.sym` audit found no duplicate label addresses and
    no overlapping `.data` / `.text` / `.image` / `.code` blocks.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Pattern Table Symbol Alias Deduplication
- **Status:** completed
- Actions taken:
  - Removed source-only same-address aliases from `Yoshi/yoshi.sym` for
    `GridPiecePatternPayload0`, `ColumnSpritePatternFrame2Block`,
    `ColumnSpritePatternFrame2Column0`, and
    `ColumnSpritePatternFrame1Column0`.
  - Kept `GridPiecePatternTable`, `ColumnSpritePatternTable`, and
    `ColumnSpritePatternFrame1Block` as the single generated-symbol labels at
    their addresses, matching the table-base references used by code.
  - Preserved the richer same-address aliases in `Yoshi/bank_000.asm`, where
    RGBDS can assemble them and they aid manual reading.
  - Synced findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label audit found no remaining duplicate
    label addresses.
  - `Yoshi/yoshi.sym` block-overlap audit found no overlapping `.data` /
    `.text` / `.image` / `.code` blocks.
  - Targeted pattern-table symbol scan shows only `GridPiecePatternTable`,
    `ColumnSpritePatternTable`, and `ColumnSpritePatternFrame1Block` at the
    formerly duplicated addresses.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Bank 3 Result-Record Graphics Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed `Bank3ResultTilesTo9000/8800` to
    `Bank3ResultRecordTilesTo9000/8800`, matching the sole confirmed
    `SetupResultRecordScreen` caller and the existing
    `BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE` constant.
  - Renamed the rendered Bank 3 matching/result-record evidence sheets from
    address-based names to destination/role names.
  - Synced `Yoshi/yoshi.sym`, graphics-load notes, architecture notes,
    findings, task-plan, and work-estimate notes.
- Test result:
  - `python3 tools/render_gb_tiles.py --preset yoshi-graphics` regenerated 19
    evidence sheets and README successfully.
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted stale-name scan found no remaining `Bank3ResultTilesTo*`,
    `bank3_result_5400`, `bank3_result_5c00`,
    `bank3_matching_4000`, `bank3_matching_4800`, or
    `bank3_matching_4e40` references in source, active docs, rendered
    manifest, or tile-render tooling.
  - Targeted new-name scan confirmed the renamed Bank 3 result-record source,
    symbol, docs, renderer, and manifest entries.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Pause Overlay OAM Template
- **Status:** completed
- Actions taken:
  - Renamed `PauseSpriteData` to `PauseOverlayOamTemplate`.
  - Added `PAUSE_OVERLAY_OAM_ENTRY_COUNT` and
    `PAUSE_OVERLAY_OAM_TEMPLATE_SIZE`, replacing the raw `$0020` copy size in
    `DrawPauseOverlay`.
  - Documented the `00:$0421-$0440` pause overlay range as eight direct
    hardware OAM entries copied to `SHADOW_OAM`.
  - Synced `Yoshi/yoshi.sym`, sprite/OAM notes, data-range notes, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted stale-name scan found no remaining `PauseSpriteData` label or raw
    `ld bc, $0020` pause-overlay copy size in source, symbols, active docs, or
    task notes.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Interrupt Vector Padding Label Cleanup
- **Status:** completed
- Actions taken:
  - Renamed the unreferenced `PositionTable` label at `00:$0068` to
    `UnusedInterruptVectorPadding`.
  - Documented that `00:$0068-$00FF` sits between the Joypad interrupt vector
    and `EntryPoint`, with no confirmed source/symbol references.
  - Synced `Yoshi/yoshi.sym`, data-range notes, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted active-source scan found no remaining `PositionTable` label in
    source, symbols, constants, or data-range notes; the only remaining
    mentions are historical rename notes in findings/progress/estimate files.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Pause HALT Opcode Restoration
- **Status:** completed
- Actions taken:
  - Replaced the raw `db $76` opcode at the end of `PauseGame` with the
    explicit `halt` instruction.
  - Documented that pause waits for the next interrupt after playing
    `SND_PAUSE` and clearing `LCD_REDRAW`, then falls through to
    `DrawPauseOverlay`.
  - Synced findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted raw-opcode scan found no remaining `db $76` in Bank 0/1 source.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 2/4: OAM DMA HRAM Routine Instruction Restoration
- **Status:** completed
- Actions taken:
  - Replaced the raw ten-byte `OAMDMARoutine` payload with explicit
    instructions: write `SHADOW_OAM_HI` to `rDMA`, wait
    `OAM_DMA_WAIT_LOOP_COUNT` decrements, then `ret`.
  - Added `WaitOAMDMATransfer` and changed the `Yoshi/yoshi.sym` block at
    `00:$01C8-$01D1` from `.data:a` to `.code:a`.
  - Synced VRAM/OAM copy notes, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted source/symbol scan found no remaining raw
    `db $3e, $c4, $e0, $46, $3e, $28, $3d, $20, $fd, $c9` OAM DMA payload and
    no remaining `00:01c8 .data:a` override.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4/5: Game Turn Table Symbol Boundary Sync
- **Status:** completed
- Actions taken:
  - Updated `Yoshi/yoshi.sym` so the recovered `GameTurnParamTable` is marked as
    one `$348`-byte data range from `00:$0B8D` through `00:$0ED4`.
  - Replaced the stale `00:$0C40` `GameTurnTable` symbol with
    `GameTurnParamTableContinuation`, matching the source-only exact-address
    landmark inside the table.
  - Corrected docs that still described the table as ending at `00:$0ED2`; the
    next code entry is `ProcessMatching` at `00:$0ED5`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the range change.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: BG Map Fill Symbol Sync
- **Status:** completed
- Actions taken:
  - Updated `Yoshi/yoshi.sym` to use the recovered Bank 0 BG-map shadow fill
    labels: `FillGameTilemap`, `FillTitleTilemap`,
    `BeginBgMapShadowFill`, and `FillBgMapShadowLoop`.
  - Replaced the stale `CalcOAMAddress` symbol with `CalcTilemapAddress` and
    added the recovered carry-continuation labels
    `AddTilemapColumnOffset`, `AddBgMapShadowBaseLow`, and
    `StoreCalculatedTilemapAddressLow`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Targeted source/symbol scan found no remaining `FillOAMGameTile`,
    `FillOAMTitleTile`, or `CalcOAMAddress` labels.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the label sync.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 1/4: Vector And Header Symbol Sync
- **Status:** completed
- Actions taken:
  - Added reset vector labels `RST_00` through `RST_38` and the five
    interrupt-vector labels to `Yoshi/yoshi.sym`.
  - Marked `00:$0000-$0067` as code in `Yoshi/yoshi.sym`, ending immediately
    before `UnusedInterruptVectorPadding`.
  - Added cartridge header labels `HeaderLogo` through `HeaderGlobalChecksum`
    and marked `00:$0104-$014F` as header data.
  - Synced data-range and findings notes with the source and rebuilt
    `Yoshi/game.sym` labels.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the vector/header sync.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Low-Level Helper Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered low-level helper labels already
    present in source and rebuilt `Yoshi/game.sym`.
  - Added joypad reset/wait labels
    `ResetJoypadStateAndReinitOnRelease` and `WaitJoypadLinesReleasedLoop`.
  - Added OAM DMA, LCD-off, shadow-OAM, and memory-copy helper labels:
    `CopyOAMDMARoutineToHRAMLoop`, `WaitForLCDOffSafeLine`,
    `StoreDisabledLCDCAndRestoreIE`, `ClearShadowOamLoop`,
    `HideShadowOamSpritesLoop`, and `CopyBytesDuplicatedLoop`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the low-level helper sync.
  - Targeted scan confirmed all synced labels appear at the same addresses in
    `Yoshi/yoshi.sym`, `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Main Loop And Pause Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered VRAM copy chunk-loop labels:
    `VRAMCopyNextChunk`, `VRAMCopyFullChunk`,
    `UnusedVRAMCopy2Setup`, `UnusedVRAMCopy2NextChunk`, and
    `UnusedVRAMCopy2FullChunk`.
  - Added MainLoop state-dispatch labels from `DispatchTitleMenuState`
    through `DispatchPreplayInitState`, plus
    `IgnoreInvalidGameStateAndLoop`, `StoreGameStateAndLoop`, and
    `RestoreMainBankAfterGameTileLoad`.
  - Added pause helper labels:
    `CheckPauseAllowedForLinkMaster`, `CheckPauseButtonInput`,
    `WaitPauseResumeInputLoop`, `PlayPauseSoundAndHalt`, and
    `WaitLinkPeerUnpauseLoop`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Startup Clear Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered startup WRAM/VRAM/HRAM clear
    labels: `CheckPersistMagicByte1`, `UseFullWRAMClear`, `BeginWRAMClear`,
    `ClearWRAMLoop`, `ClearWRAMByte`, `ClearVRAMLoop`, and
    `ClearHRAMWorkAreaLoop`.
  - Added the recovered hardware tilemap fill helper labels
    `BeginHardwareTilemapFill` and `FillHardwareTilemapLoop`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the startup symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Math And Sprite Helper Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered Bank 0 math helper labels:
    `MultiplyShiftMultiplierLoop`, `AddShiftedMultiplicandToProduct`,
    `MultiplyAddCarryChain`, `ShiftMultiplicandForNextBit`,
    `CountMaskedMultiplyBitsLoop`, and
    `ContinueMaskedMultiplyBitCount`.
  - Synced sprite-object helper labels:
    `TickSpriteObjectWaitPhase`, `WriteBackSpriteObjectStaging`,
    `AdvanceAfterConditionalSpriteByte0`,
    `AdvanceAfterConditionalSpriteByte1`,
    `AdvanceAfterConditionalSpriteByte2`, and
    `ReturnAfterConditionalSpriteBytes`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the math/sprite helper symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Column And Grid Draw Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered column-sprite helper labels:
    `ReadColumnTopRowForSprite`,
    `UnreachedColumnSpriteAlternateRowFragment`,
    `UnreachedColumnSpriteWrapRow`,
    `UnreachedColumnSpriteContinueAtRow1`, and
    `DrawColumnSpriteRow0..2`.
  - Added the grid-piece, column-clear, and all-column draw helper labels:
    `DrawGridPieceWithinBounds`, `DrawGridPieceSecondRow`,
    `ClearColumnLeftLoop`, `ClearColumnLeftNextTilemapPage`,
    `ReturnFromClearColumnLeft`, `ClearColumnRightLoop`,
    `ReturnFromClearColumnRight`, `DrawAllColumnsColumnLoop`,
    `DrawAllColumnsRowLoop`, and `AdvanceDrawAllColumnsColumn`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the column/grid draw helper symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Drop And Collision Animation Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered drop cascade helper labels from
    `BeginDropDownCascade` through `SwapColumnTopRowsAfterDrop`.
  - Added the collision scan and drop-position update helper labels:
    `ScanDropCollisionSpriteSlotsLoop`, `SkipInactiveDropCollisionSlot`,
    `AdvanceDropCollisionSlot`, `ReturnDropCollisionDetected`,
    `UpdateDropPositionsLoop`, and `AdvanceDropPositionSlot`.
  - Synced the drop-down/drop-up redraw and boundary helper labels from
    `RedrawDropDownState1` through `DrawDropUpFinalPiece`, plus
    `ClearAnimStateLoop`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the drop/collision animation symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Blink And Game-State Init Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered `StartDropAnim` return label
    and unused board-pattern helper labels:
    `ReturnFromStartDropAnim`, `UnusedBoardPatternColumnLoop`,
    `ClearUnusedBoardPatternLeadingBytes`,
    `FillUnusedBoardPatternIndexBytes`, and
    `StoreUnusedBoardPatternTailByte`.
  - Added the recovered column blink helper labels from
    `BeginColumnBlinkSlotScan` through `AdvanceColumnBlinkSlot`.
  - Added the game-state init and drop-cursor helper labels:
    `InitSinglePlayerLevelSpeedSettings`,
    `InitTwoPlayerLevelSpeedSettings`, `AdvanceDropCursorAltFrame`,
    `StoreAdvancedDropCursorFrame`, and
    `StopDropCursorFrameAnimation`.
  - Skipped same-address aliases such as `GridPiecePatternPayload0` and
    `ColumnSpritePatternFrame2Column0`, keeping `Yoshi/yoshi.sym`'s
    no-duplicate-label audit clean.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the blink/init symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Matching And Result Panel Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered `ProcessMatching` helper
    labels from `StoreMatchingStateAndLoadGraphics` through
    `MoveMatchingFinalOamUpLoop`.
  - Added matching/result score helper labels:
    `WaitMatchingScoreSoundEndLoop` and `DrawResultScoreDigitsLoop`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the matching/result panel symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Gameplay Input And Piece Helper Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered `FillRect`,
    `UpdateGameplayObjectSlotsAndRoundState`, `UpdatePieceFallTimer`,
    `UpdatePieceDisplayByGameType`, `CheckGameplayObjectSlotsActive`, and
    `UpdateFallAcceleration` helper labels.
  - Added playfield input, fast-fall clamp, falling-piece landing, gameplay
    object clear, selected-column, board staging, B-type timing/init, initial
    board fill, rotation, level-delay, landing-progress, board-scan, timer, and
    2P round-complete tile-slot helper labels.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the gameplay/input/piece helper symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Round Transition And Piece Display Menu Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered 2P round-transition and result
    helper labels: `SendRoundTransitionFrameLoop`,
    `PlayRoundTransitionDefaultSound`, `ApplyRoundCompleteReward`,
    `AbortSend2PDataFrames`, `RoundCompleteStateRemapTable`, and
    `RoundCompleteDelayParamTable`.
  - Added piece-display state builder, object builder, game-turn, menu
    selection, field-occupancy, forced-state, pending-field-rise, and
    piece-display blink helper labels from `Yoshi/bank_000.asm`.
  - Corrected stale same-address labels in `Yoshi/yoshi.sym`:
    `TitleScreenLoop` is now `ApplyAllForcedPieceDisplayStates`, and the old
    `DrawTextBox` / `DrawTextString` / `ClearTextArea` labels at
    `00:$1BD0-$1BFD` are now `UpdatePieceDisplayBlink`,
    `TogglePieceDisplayFrame`, and `ResetPieceDisplayBlinkTimer`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the round-transition/menu/blink symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Same-address label comparison for `00:$1800-$1C50` found no remaining
    `Yoshi/yoshi.sym` / `Yoshi/game.sym` mismatches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Option UI And Detached Preplay Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered option box, text, marker, and
    cursor-highlight labels from `DrawOptionDecorationTilesLoop` through
    `OptionCursorBgmHighlightTileTriplets`.
  - Added settings cursor init labels, detached preplay input/option branches,
    BGM preview setting branches, option value drawing labels, and the serial
    interrupt tail labels through `FinishSerialInterrupt`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the option UI/detached preplay symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Same-address label comparison for `00:$1C00-$2100` found no remaining
    `Yoshi/yoshi.sym` / `Yoshi/game.sym` mismatches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Title And Field Animation Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered title string-copy and run-menu
    labels: `CopyStringToGridLoop`, `AdvanceStringGridRow`, and
    `RunTitleMenu`.
  - Added 2P preplay initialization labels and field-animation slot helper
    labels from `UpdateFieldAnimSlot11` through `FieldRowDeltaTable`.
  - Corrected stale same-address labels in `Yoshi/yoshi.sym`:
    `InitGameVars`, `Setup2PField`, `SetupLinkCable`, `DrawField1`,
    `DrawField2`, `DrawField3`, `DrawField4`, `DrawFieldBorder`,
    `DrawFieldTile`, and `DrawFieldRow` now use the recovered field-animation
    source names.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the title/field-animation symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Same-address label comparison for `00:$2100-$2500` found no remaining
    `Yoshi/yoshi.sym` / `Yoshi/game.sym` mismatches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: 2P Preplay Text And Settings Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered 2P preplay role-header text,
    speed text, level-preview text, settings exchange, and result-record init
    labels.
  - Represented the same-address `PiecePreviewText0` /
    `PiecePreviewTextTable` source alias as `PiecePreviewTextTable` in
    `Yoshi/yoshi.sym`, preserving the no-duplicate-label audit.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the 2P preplay text/settings symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Multi-label aware same-address comparison for `00:$2500-$2B00` found no
    remaining `Yoshi/yoshi.sym` / `Yoshi/game.sym` mismatches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: 1P Preplay Countdown Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with recovered 1P preplay header/game-type/BGM
    text data labels, detached label-tile helper labels, settings cursor frame
    clear loop label, countdown digit buffer build/blit labels, and countdown
    digit pattern labels.
  - Kept `00:$2FFB` represented as `CountdownDigitPatternTable` in
    `Yoshi/yoshi.sym` because the source has the same-address
    `CountdownDigitPattern0` alias and the symbol-file duplicate-label audit
    remains intentionally strict.
  - Corrected stale `00:$31D1` in `Yoshi/yoshi.sym` from `FormatRankEntry` to
    the recovered source label `QueueRoundResult`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the 1P preplay/countdown symbol sync.
  - Targeted scan confirmed the synced labels appear in `Yoshi/yoshi.sym`,
    `Yoshi/game.sym`, and `Yoshi/bank_000.asm`.
  - Multi-label aware same-address comparison for `00:$2B00-$3850` found no
    remaining `Yoshi/yoshi.sym` / `Yoshi/game.sym` mismatches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Round-End Link-Result Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered Bank 0 round-end flow,
    score-ranking, link-result screen/confirm, A-type round-complete summary,
    manual-OAM bonus animation, and ROM0 tail graphics data labels from
    `00:$304B-$3E49`.
  - Moved the earlier partial link-result / round-complete summary labels into
    address order under the Bank 0 round-end/link-result sections, avoiding
    duplicate same-address symbol entries.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - `Yoshi/yoshi.sym` duplicate-label and block-overlap audits returned no
    matches after the round-end/link-result symbol sync.
  - Multi-label aware same-address comparison for `00:$304B-$3E49` found no
    remaining `Yoshi/yoshi.sym` / `Yoshi/game.sym` mismatches.
  - Missing-label scan for `00:$304B-$3E49` found no remaining
    `game.sym` labels absent from `Yoshi/yoshi.sym`.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Bank 0 Final Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced the remaining Bank 0 matching/result OAM template and data-table
    labels in `Yoshi/yoshi.sym`: `MatchingOamTemplateTop`,
    `MatchingOamTemplateMiddle`, `MatchingOamTemplateFinal`,
    `MatchingScoreBonusTable`, `MatchingTileBaseIndexTable`, and
    `UnusedDrawVerticalTilePairUnlessFF`.
  - Corrected stale same-address `Yoshi/yoshi.sym` labels around piece-display
    shuffle/init helpers: `ShufflePieceDisplaySlotOrder`,
    `SelectPieceDisplaySlotOrderEntry`, `ShufflePieceDisplayCodePool`,
    `SelectPieceDisplayCodePoolEntry`, `SeedColumnTopRows`,
    `InitPieceDisplaySlotOrder`, and `InitPieceDisplayCodePool`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Bank 0 `game.sym` / `Yoshi/yoshi.sym` missing-label and same-address
    mismatch scans now return no matches.
  - `Yoshi/yoshi.sym` duplicate-label audit returned no matches.

### Phase 4: Bank 1 Sprite Frame Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with Bank 1 sprite frame data labels from
    `01:$40A0-$42F4`, covering `SpriteUpdatePointerTable`,
    `SpriteFrameTable_*`, `SpriteTileList_*`, and `SpriteLayout_*`.
  - Removed stale `SetupSpriteAnim` / `ProcessSpriteFrame` labels that were
    still pointing into the recovered sprite frame data block.
  - Represented the same-address `SpriteLayout_TwoTileRow` /
    `SpriteTileList_PieceDisplayFrame22` source alias as
    `SpriteLayout_TwoTileRow` in `Yoshi/yoshi.sym`, preserving the
    no-duplicate-label audit.
  - Fixed the Bank 2 `TitleTileSet` `.data` directive from `$1000` to `$0F70`
    so the symbol-file data blocks no longer overlap the nested
    `TwoPlayerNonMasterTiles` range. The title copy still uses
    `BANK2_TITLE_TILE_SET_COPY_SIZE` (`$1000`) from the `TitleTileSet` label.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - Bank 1 `01:$40A0-$42F4` missing-label and same-address mismatch scans
    returned no matches.
  - Case-normalized global same-address mismatch scan now returns no matches;
    the remaining `game.sym` labels absent from `Yoshi/yoshi.sym` are all in
    Bank 1, currently 501 addresses.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Bank 1 HUD And Timer Symbol Sync
- **Status:** completed
- Actions taken:
  - Corrected `Yoshi/yoshi.sym` `StoreScoreDigitsFromBCD` from `01:$4354` to
    the recovered source address `01:$4353`.
  - Synced Bank 1 score/field/text labels in `Yoshi/yoshi.sym`:
    `FieldColumnTilePatternTable`, `EggTextFrame0..2TileRows`,
    `TitleLabelTextPlayer`, and `TitleLabelTextYoshi`.
  - Synced Bank 1 playfield side-panel and role-header helper labels from
    `01:$484C-$49D5`, including the coordinate-selection branches and the
    unreferenced `UnusedDrawPlayfieldGameTypeHeader` fragment.
  - Synced Bank 1 wave-update and elapsed-timer helper labels from
    `01:$4BFE-$4C88`, including `FillWaveRamWithFFLoop`,
    `FinishWavePatternUpdate`, `CheckTotalElapsedTimer`, and
    `ClampElapsedTimerDigits`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - Bank 1 `01:$432F-$4C88` missing-label and same-address mismatch scans
    returned no matches.
  - Remaining `game.sym` labels absent from `Yoshi/yoshi.sym` are all in
    Bank 1, currently 466 addresses.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Bank 1 Sound Parser And Setup Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with the recovered Bank 1 sound-channel update,
    sound sequence parser, note/output, pitch-slide, helper multiply, sound
    engine dispatch, and `StartSoundSequence` helper labels from
    `01:$4C91-$5668`.
  - Kept the existing sound setup data boundary at `01:$55E2 .code:87` and
    `01:$5669 SoundWaveDutyData` while adding internal code labels inside that
    block.
  - Updated the source-recovery checklist progress to 348 / 362 items complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - Bank 1 `01:$4C91-$5668` missing-label and same-address mismatch scans
    returned no matches.
  - Remaining `game.sym` labels absent from `Yoshi/yoshi.sym` are all in
    Bank 1, currently 365 addresses.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Bank 1 Sound Data Symbol Sync
- **Status:** completed
- Actions taken:
  - Synced `Yoshi/yoshi.sym` with all remaining Bank 1
    `SoundSequenceData_*` and `MusicSequenceData_*` internal labels from
    `01:$569A-$7BDF`.
  - Synced Bank 1 sound index entries and tail sound/wave data labels from
    `01:$7C2C-$7FE3`.
  - Kept `SoundIndexTable` as the canonical `01:$7C2C` label and used one
    canonical label per same-address sound-index alias so the symbol-file
    duplicate-label audit stays clean.
  - Updated the source-recovery checklist progress to 350 / 364 items complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count is now 0.
  - Bank 1 same-address mismatch scan returned no matches.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Remaining Sound Index Entry Audit
- **Status:** completed
- Actions taken:
  - Named the `SoundIndexTable` flag masks used by `SoundLookupIndex` and
    `StartSoundSequence`: `SOUND_INDEX_ENTRY_COUNT_BITS`,
    `SOUND_INDEX_ENTRY_COUNT_FIELD_MASK`, and
    `SOUND_INDEX_ENTRY_CHANNEL_MASK`.
  - Replaced the corresponding raw `$C0`, `$03`, and `$0F` masks in
    `Yoshi/bank_001.asm`.
  - Re-audited remaining numeric sound index entries after the Bank 1
    `yoshi.sym` sync. The high flag bits identify adjacent continuation entries
    for multi-channel sound starts; the remaining numeric entries are not
    independently proven public `PlaySound` IDs.
  - Checked sequence data for a nested `$EF` sound-command producer. The only
    sound-data `$EF` byte found by the current source scan is the low byte of
    the `$FE` loop target `$6BEF`, not a nested sound command.
  - Updated `docs/source_recovery/sound_engine.md` and marked the remaining
    effect-ID audit complete in `task_plan.md`.
  - Updated the source-recovery checklist progress to 351 / 364 items complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Bank 2/3 Screen-Level Tile Block Map
- **Status:** completed
- Actions taken:
  - Added a screen-level Bank 2/3 tile-block map to
    `docs/source_recovery/graphics_loads.md`, connecting each confirmed
    graphics-bank load to its game state or screen family.
  - Documented final observed VRAM composition for title init,
    pre-play/settings init, gameplay setup, matching/result panel,
    result-record/high-score, link result, and terminal link-result overlay
    flows.
  - Kept the remaining uncertainty scoped to per-tile semantics inside broad
    Bank 3 screen ranges rather than the now-mapped screen/destination roles.
  - Marked the Bank 2/3 tile-block screen/destination map complete in
    `task_plan.md`.
  - Updated the source-recovery checklist progress to 352 / 364 items complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3/4: Bank 0/1 Code/Data Boundary Audit
- **Status:** completed
- Actions taken:
  - Added the current Bank 0/1 boundary audit to
    `docs/source_recovery/data_ranges.md`.
  - Recorded the remaining intentional Bank 0/1 `.code` islands:
    `00:$0000`, `00:$01C8`, `01:$55E2`, `01:$7C02`, and `01:$7C08`.
  - Updated stale Bank 1 music-stream rows to the current `.data`
    boundaries: `01:$5FE3 .data:11ae`, `01:$71C1 .data:23`,
    `01:$77B6 .data:50`, and `01:$7806 .data:3fc`.
  - Marked the Bank 0/1 code/data misclassification split complete in
    `task_plan.md`.
  - Updated the source-recovery checklist progress to 353 / 364 items
    complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 1/4: Interrupt-Sensitive Bank Assumption Audit
- **Status:** completed
- Actions taken:
  - Audited every current `MBC1_ROM_BANK_REG` write in Bank 0/1 source.
  - Documented the interrupt-sensitive bank policy in
    `docs/source_recovery/baseline.md`: VBlank is the only banked ISR and
    requires Bank 1 active while LCD-on VBlank interrupts can occur.
  - Recorded that Bank 2/3 graphics selections are confined to LCD-off setup
    windows and restore `ROM_BANK_MAIN_CODE` before normal execution resumes.
  - Recorded that the serial interrupt handler is entirely in ROM0 and does
    not depend on the current switch bank.
  - Marked the interrupt-sensitive bank-assumption checklist item complete in
    `task_plan.md`.
  - Updated the source-recovery checklist progress to 354 / 364 items
    complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 3: State-Path Trace Coverage Audit
- **Status:** completed
- Actions taken:
  - Re-audited current `GAME_STATE` writers and state dispatch coverage.
  - Added a trace coverage section to `docs/source_recovery/state_machine.md`
    for title, options/pre-play, gameplay, round-end/result, and 2P routes.
  - Documented that no distinct demo/attract-loop `GAME_STATE` has been
    recovered in the current source; the idle title loop remains
    `GAME_STATE_TITLE_MENU` until input or link handshake enters pre-play.
  - Marked the title/demo/gameplay/round/options/2P path trace item complete
    in `task_plan.md`.
  - Updated the source-recovery checklist progress to 355 / 364 items
    complete.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Falling Piece Grid Column Rename
- **Status:** completed
- Actions taken:
  - Rechecked the old `PIECE_ROTATION` variable at `$C691` against the current
    sprite-object staging layout.
  - Confirmed `$C691` is `SPRITE_OBJECT_STAGING + SPRITE_OBJECT_GRID_COLUMN`,
    copied from the active gameplay sprite slot by `UpdateSpriteObject`.
  - Renamed `PIECE_ROTATION` to `FALLING_PIECE_GRID_COLUMN` in source and
    recovery notes.
  - Renamed the misleading `UpdateTimer` round-transition helper to
    `RunBoardScanRoundTransition`, and renamed the internal `Process2Player`
    label to `SendRoundTransitionPreFrame1`.
  - Updated `docs/source_recovery/board_layout.md`,
    `docs/source_recovery/column_state.md`, and
    `docs/source_recovery/memory_map.md` to record that this byte is a column
    index, not a rotation state; updated fall/data/memory notes to use the
    new round-transition helper name.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Matching Result Stats Routine Rename
- **Status:** completed
- Actions taken:
  - Rechecked the old `UpdateLevel` routine against its two callers in
    `ProcessMatching` and the matching score-bonus tail.
  - Confirmed the routine draws the matching/result screen score, level, speed,
    and elapsed-time display rather than updating level state.
  - Renamed `UpdateLevel` to `DrawMatchingResultStats` in source and
    `Yoshi/yoshi.sym`.
  - Renamed the generic `UpdateScore` label to
    `ApplyMatchingScoreBonusAndWait`, matching its score-bonus and input-wait
    role.
  - Updated the result-screen memory map, findings, work estimate, and task
    checklist wording to use the new role name.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.

### Phase 4: Piece Display State Builder Rename
- **Status:** completed
- Actions taken:
  - Rechecked the old `DisplayResults` routine against its callers and the
    `PIECE_DISPLAY_STATES` producer path.
  - Confirmed the routine stores the requested display count in `SCREEN_STATE`,
    applies pending 2P field-rise adjustments through
    `SelectEffectivePieceDisplayCount`, clears `PIECE_DISPLAY_STATES`, then
    fills state entries selected through `PIECE_DISPLAY_SLOT_ORDER` and
    `PIECE_DISPLAY_CODE_POOL`.
  - Renamed `DisplayResults` to `BuildPieceDisplayStatesForCount` in source,
    constants, symbols, and active recovery notes.
  - Renamed the generic `ProcessMenuInput` helper to
    `ClearPieceDisplayObjectSlots`, matching its slot 5-8 type/frame clear
    behavior.
  - Renamed the generic `InitTitleGfx` helper to
    `CountFieldOccupancyIntoUiScratch`; it clears `UI_SCRATCH` and counts
    non-empty entries in the `FIELD_OCCUPANCY_SCAN_TOP_LEFT` sample.
  - Renamed the misleading `DrawTitleText` / `AnimateTitle` pair to
    `AddNonForcedPieceDisplayObjectsToUiScratch` and
    `AddPieceDisplayObjectToUiScratch`, matching the fact that they add
    non-forced piece-display objects into the same `UI_SCRATCH` count.
  - Renamed the remaining game-turn piece-display scheduler labels:
    `ProcessMenuLoop` to `LoadGameTurnPieceDisplayStep`, `UpdateMenuCursor`
    to `UpdateGameTurnPieceDisplay`, `DrawMenuCursor` to
    `InitGameTurnPieceDisplay`, and the delay stores to
    `StoreGameTurnPieceDelay` / `StoreInitialGameTurnPieceDelay`.
  - Renamed the effective count and code-selection helpers:
    `SelectMenuItem` to `SelectEffectivePieceDisplayCount`,
    `SelectTwoPlayerMenuState` to `SelectTwoPlayerPieceDisplayCount`,
    `ConsumePendingFieldRise` to `ConsumePendingFieldRiseForDisplayCount`, and
    `ProcessMenuSelection` to `SelectPieceDisplayCode`.
  - Renamed `TitleInputHandler` to `TickTitleLevelDisplayDigits`; it advances
    and redraws the title/preplay level display every
    `LEVEL_DISPLAY_TICK_PERIOD` ticks.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: Gameplay And Result Record Role Rename
- **Status:** completed
- Actions taken:
  - Rechecked the gameplay object update hub and B-type clear path.
  - Renamed `UpdateGameplayObjectSlotsAndRoundState` to
    `UpdateGameplayObjectsAndCheckBTypeClear`, matching its object-slot update,
    active-object fall timer branch, and B-type all-columns-clear check.
  - Renamed `ProcessBTypeClearHighScore` to
    `ProcessBTypeClearRoundResult`, matching the B-type clear path that
    optionally queues the 2P round result before entering high-score/result
    processing.
  - Rechecked the old `UpdateGameField` routine and confirmed it is the 2P
    pre-play level/speed settings exchange, not field logic.
  - Renamed `UpdateGameField` to `Exchange2PPreplaySettings`, and renamed the
    result-record helpers `RefreshField` to `InitResultRecordsIfNeeded` and
    `ClearField` to `ProcessCurrentResultRecordAndSetupScreen`.
  - Updated Bank 1 cross-bank call sites and active recovery notes to use the
    new names.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after updating the two Bank 1 call
    sites.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 4: VBlank BG Map Shadow Copy Rename
- **Status:** completed
- Actions taken:
  - Rechecked the old `ProcessFieldLogic` routine in Bank 1 and confirmed it
    runs from `VBlankHandler` while `BG_MAP_SHADOW_COPY_ENABLE_FLAG` is
    nonzero.
  - Renamed it to `CopyNextBgMapShadowSlice`, matching the three-phase copy of
    six `BG_MAP_SHADOW` rows into hardware BG map VRAM using
    `BG_MAP_COPY_PHASE`.
  - Updated the symbol file and recovery notes so `$FFA6` is tied to the BG map
    shadow copy phase, not to gameplay field logic.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Case-normalized duplicate-label and block-overlap audits for
    `Yoshi/yoshi.sym` returned no matches.
  - The `game.sym` labels absent from `Yoshi/yoshi.sym` count remains 0.
  - Raw `$Cxxx` count in Bank 0/1 remains 0.
  - Raw direct branch, generated `jr_000_*`, and anonymous relative `@+` /
    `@-` scans returned no matches.
  - `git diff --check` passed.

### Phase 5: Board Clear, A-Type Display Init, And Initial Board Duplicate-Avoidance Rename
- **Status:** completed
- Actions taken:
  - Renamed `GenerateNextPiece` to `ClearBoardData`; the routine clears the
    full `$40` bytes of `BOARD_DATA` and does not itself generate a piece.
  - Renamed `SetArrayElement` to `InitATypeGameTurnPieceDisplay`; the routine is
    the A-type setup wrapper that calls `InitGameTurnPieceDisplay`.
  - Renamed `RotatePiece` to `AvoidInitialBoardAdjacentDuplicate`; the routine
    adjusts only generated initial-board candidates that match the already
    filled cell two bytes ahead, then restores the board write pointer.
  - Updated `Yoshi/yoshi.sym`, `board_layout.md`, `memory_map.md`, and
    `piece_display_state.md`, `findings.md`, and `work_plan_and_estimate.md`
    to keep the setup, board-storage, and initial-board generation notes
    aligned.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.

### Phase 5: Gameplay Frame And Field Column Tile Pattern Rename
- **Status:** completed
- Actions taken:
  - Renamed `GameMainUpdate` to `RunGameplayFrame`, matching the per-frame
    playing-state update called from the Bank 0 main loop.
  - Renamed `Check2PGameState` to `ProcessPending2PRoundResult`; it is the
    2P-only tail that consumes `ROUND_RESULT_PENDING` and enters
    `ProcessRoundResultAndEnterRoundEnd` with `ROUND_RESULT_CODE`.
  - Renamed `SetupGameBG` to `DrawGameplayBgTopRowIfNoResultFlow`; it redraws
    only the normal gameplay BG top row and returns early while
    `RESULT_FLOW_ACTIVE` is set.
  - Renamed `LoadGameBGTiles` to `DrawFieldColumnTilePattern`; it indexes
    `FieldColumnTilePatternTable` with `FIELD_COLUMN_TILE_PATTERN_INDEX` and
    copies one 16-byte pattern to `FIELD_COLUMN_TILE_PATTERN_DEST_COORD`.
  - Updated the Bank 0 cross-bank call sites, `Yoshi/yoshi.sym`, and active
    recovery notes to use the new names.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `git diff --check` passed.
  - Stale-name search outside this progress log for the four old labels
    returned no matches.

### Phase 5: Drop Cursor Animation Routine Rename
- **Status:** completed
- Actions taken:
  - Renamed `InitGameState2` to `UpdateDropCursorAnimation`; the routine is the
    per-frame slot-0 cursor animation step gated by `DROP_CURSOR_ANIM_ACTIVE`.
  - Renamed `InitGameBoard` to `InitDropCursorAnimationState`; the routine only
    clears `DROP_CURSOR_ANIM_ACTIVE` and seeds `DROP_CURSOR_FRAME_TIMER`.
  - Updated the Bank 1 call sites, `Yoshi/yoshi.sym`, and active recovery notes
    for the drop cursor animation state.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Stale-name search outside this progress log for `InitGameState2` and
    `InitGameBoard` returned no matches.

### Phase 5: Score Reset Routine Rename
- **Status:** completed
- Actions taken:
  - Renamed `InitGameScreen` to `ResetScoreAccumulatorAndDigits`; the routine
    saves `SCORE_PRESERVED_UNUSED_BYTE`, clears the packed BCD accumulator and
    five display digits from `SCORE_BCD_LOW`, then restores the preserved byte.
  - Updated the Bank 0/1 call sites, `Yoshi/yoshi.sym`, the score constant
    comment, and active recovery notes to use the narrower score-reset name.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Stale-name search outside this progress log for `InitGameScreen` returned
    no matches.

### Phase 5: Unused BCD Tile Pair Fragment Rename
- **Status:** completed
- Actions taken:
  - Rechecked the old `DrawBCDNumber` label and found no call/jump references
    to the fragment in the current Bank 0/1 source.
  - Renamed it to `UnusedDrawTwoDigitBcdTilePair`, with local tails
    `UseBlankUnusedBcdTensTile` and `StoreUnusedBcdDigitTiles`.
  - Documented the unused fragment in `findings.md` and updated the active work
    estimate/progress names.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Old-name search for `DrawBCDNumber`, `UseBlankBcdTensTile`, and
    `StoreBcdTensTile` returned no matches.

### Phase 5: Unused Low-Nibble Tile Digit Fragment Rename
- **Status:** completed
- Actions taken:
  - Rechecked `DrawLowNibbleTileDigitsLoop` and found no call/jump references
    to its surrounding helper in the current Bank 0/1 source.
  - Added the explicit fragment entry label
    `UnusedDrawLowNibbleTileDigitsByCoord` at `01:$4321`, and renamed the loop
    to `UnusedDrawLowNibbleTileDigitsLoop`.
  - Updated `Yoshi/yoshi.sym`, `findings.md`, and active recovery notes so the
    fragment is not mistaken for a live shared digit renderer.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Direct call/jump search for the unused low-nibble helper returned no
    matches.

### Phase 5: Egg Text Frame Renderer Rename
- **Status:** completed
- Actions taken:
  - Renamed `AnimateSprite` to `DrawEggTextFrameByIndex`; all confirmed callers
    pass egg-text frame indices from the egg text/count animation paths.
  - Renamed `ReturnFromAnimateSpriteIn2P` to
    `ReturnFromEggTextFrameDrawIn2P`.
  - Renamed `SpriteAnimTextFrame0..2` to `EggTextFrame0..2TileRows`, matching
    their four `$FF`-terminated tile rows consumed by `DrawStringToGrid`.
  - Updated `Yoshi/yoshi.sym`, memory-map/data-range notes, egg-counter notes,
    findings, and progress references.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `git diff --check` passed.
  - Stale-name search outside this progress log for `AnimateSprite`,
    `ReturnFromAnimateSpriteIn2P`, and `SpriteAnimTextFrame*` returned no
    matches.

### Phase 5: Egg Count Display And Refresh Rename
- **Status:** completed
- Actions taken:
  - Renamed `DrawEggCount` to `DrawPlayfieldEggCountDigits`; the routine draws
    the ones/tens egg-count digits into the gameplay tilemap coordinate chosen
    by game type.
  - Renamed `DrawEggCountAtSelectedCoord` to
    `DrawPlayfieldEggCountDigitsAtCoord` and `DrawEggCountAfterIncrement` to
    `RefreshEggCountDigitsAfterIncrement`, keeping the local branch names tied
    to their proven tilemap-write behavior.
  - Renamed `IncrementEggCounter` to `IncrementEggCountAndRefreshDisplay`; the
    routine advances the decimal egg-count digits, triggers the egg-text pulse
    on digit wraps, caps at 999, and refreshes the displayed digits.
  - Renamed `ClearEggCount` to `ClearEggCountDigitsAndUnusedByte`, preserving
    the evidence that the adjacent `$C6D2` byte is cleared with the counter but
    has no confirmed reader.
  - Updated Bank 0/1 call sites, `Yoshi/yoshi.sym`, findings, memory-map notes,
    and the egg-counter recovery note.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for the old egg-count labels
    returned no matches.
  - `git diff --check` passed.

### Phase 5: Drop Column Swap Animation Entry Rename
- **Status:** completed
- Actions taken:
  - Renamed `ClearAnimState` to `ClearDropAnimationState`; the routine clears
    `DROP_ANIM_CLEAR_SIZE` bytes starting at `DROP_ANIM_ACTIVE`, matching the
    documented drop-animation state span.
  - Renamed `ClearAnimStateLoop` to `ClearDropAnimationStateLoop`.
  - Renamed `StartDropAnim` to `StartDropColumnSwapAnimation`; the routine
    stores the selected column, seeds the first down/up cascade entries, starts
    the frame timer, and marks the column swap/drop cascade active.
  - Renamed `ReturnFromStartDropAnim` to
    `ReturnFromStartDropColumnSwapAnimation`, preserving the existing early
    return when another drop animation is already active.
  - Updated Bank 0/1 call sites, `Yoshi/yoshi.sym`, findings, memory-map notes,
    sound notes, and the drop-animation recovery note.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for the old drop-animation
    entry labels returned no matches.
  - `git diff --check` passed.

### Phase 5: Falling Piece Motion And Landing Rename
- **Status:** completed
- Actions taken:
  - Renamed `UpdateMatchState` to `UpdateFallingPieceMotionAndLanding`; the
    routine is gated by `PIECE_FALL_TIMER`, advances `PIECE_FALL_POS` and the
    staged sprite Y position, handles scan/landing behavior, writes landed
    payloads to the board, and enters the overflow result path when the column
    top underflows.
  - Updated the `UpdateSpriteObject` call site and `Yoshi/yoshi.sym`.
  - Updated active recovery notes so fall/landing behavior no longer hangs on
    the misleading match-only label.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `UpdateMatchState`
    returned no matches.
  - `git diff --check` passed.

### Phase 5: Board Scan No-Target Landing Rename
- **Status:** completed
- Actions taken:
  - Renamed `HandlePieceLanding` to `FinishBoardScanNoTargetLanding`; the entry
    is reached only from `ScanBoard` when `FindBoardScanTargetRow` returns no
    `BOARD_SCAN_TARGET_PAYLOAD`.
  - Documented that this no-target path spawns the landing field-column effect,
    clears the current gameplay object, plays `SND_PIECE_LAND`, discards the
    scan return address, and exits the falling-piece update without staging the
    scan trigger payload into `BOARD_DATA`.
  - Updated `Yoshi/yoshi.sym`, board-layout notes, sound notes, data-range
    notes, and findings.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `HandlePieceLanding`
    returned no matches.
  - `git diff --check` passed.

### Phase 5: Board Scan Trigger Sequence Rename
- **Status:** completed
- Actions taken:
  - Renamed `ScanBoard` to `RunBoardScanTriggerSequence`; the routine is called
    only for staged `BOARD_SCAN_TRIGGER_PAYLOAD`, then finds a target row,
    handles the no-target landing exit, or runs the scan animation, link field
    event payload setup, round-transition sequence, reward score lookup, and
    egg-count refresh.
  - Updated the `UpdateFallingPieceMotionAndLanding` call site and
    `Yoshi/yoshi.sym`.
  - Updated board-layout, fall-timing, memory-map, sound, findings, and
    architecture notes so the name describes the trigger-payload sequence
    rather than a generic board scan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `ScanBoard` returned no
    matches.
  - `git diff --check` passed.

### Phase 5: Board Scan Reward Score Table Rename
- **Status:** completed
- Actions taken:
  - Renamed `RoundCompleteDelayParamTable` to
    `BoardScanRewardScoreDeltaTable`; the data is a big-endian BCD score-delta
    table indexed by `ROUND_COMPLETE_PARAM_INDEX * 2` before calling
    `AddScore`, not a delay table.
  - Renamed `ApplyRoundCompleteReward` to
    `ApplyBoardScanRewardScoreAndEggCount`; the tail sends the final transition
    frames, queues the link field-event payload, applies the score delta,
    redraws the countdown digit slots, increments the egg count display, and
    clears the round-transition sprite object.
  - Updated `Yoshi/yoshi.sym`, data-range notes, memory-map notes,
    board-layout notes, and findings.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `ApplyRoundCompleteReward`
    and `RoundCompleteDelayParamTable` returned no matches.
  - `git diff --check` passed.

### Phase 5: Board Scan Reward Index Rename
- **Status:** completed
- Actions taken:
  - Renamed `ROUND_COMPLETE_PARAM_INDEX` to `BOARD_SCAN_REWARD_INDEX`; `$C6A2`
    is the reward score table index used by `ApplyBoardScanRewardScoreAndEggCount`
    after `RunBoardScanRoundTransition` saves the pre-remap `SCREEN_STATE`.
  - Renamed `StoreBoardScanDistanceParam` to
    `StoreBoardScanDistanceRewardIndex`; before the transition remap, the same
    byte temporarily stages the derived scan distance, with the one-step case
    mapping to reward index zero.
  - Updated `Yoshi/yoshi.sym`, constants, board-layout notes, data-range notes,
    memory-map notes, and findings.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `ROUND_COMPLETE_PARAM_INDEX`
    and `StoreBoardScanDistanceParam` returned no matches.
  - `git diff --check` passed.

### Phase 5: Board Scan Transition Frame Limit Table Rename
- **Status:** completed
- Actions taken:
  - Renamed `RoundCompleteStateRemapTable` to
    `BoardScanTransitionFrameLimitTable`; `RunBoardScanRoundTransition` indexes
    it with the pre-remap `SCREEN_STATE`, writes the selected transition frame
    limit back to `SCREEN_STATE`, and uses that value for the round-transition
    sprite frame/send loop.
  - Updated `Yoshi/yoshi.sym`, data-range notes, memory-map notes, and findings.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `RoundCompleteStateRemapTable`
    returned no matches.

### Phase 5: 2P B-Type Clear Gameplay-Frame Unwind
- **Status:** completed
- Actions taken:
  - Traced the B-type clear branch in `UpdateGameplayObjectsAndCheckBTypeClear`.
    In the 2P path, `QueueRoundResult` raises `ROUND_RESULT_PENDING` /
    `RESULT_FLOW_ACTIVE`, then the shared `ProcessBTypeClearRoundResult`
    tail reaches `pop af` after the saved AF has already been removed, so that
    `pop` discards `RunGameplayFrame`'s return address and exits directly to
    the playing-state main-loop continuation after `ProcessRoundResultAndEnterRoundEnd`.
  - Added a source comment at the stack-unwind site and documented the behavior
    in `result_records.md` and `findings.md`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.

### Phase 5: Matched Landing Scan-State Entry Rename
- **Status:** completed
- Actions taken:
  - Renamed `UpdateLandingProgress` to `HandleMatchedLandingScanState`; the
    entry is reached only after `HandleFallingPieceReachedColumn` has staged the
    falling payload, compared it with the current selected board cell, found a
    match, and excluded the `BOARD_FALL_END_ROW` terminal case.
  - Kept the name scoped to the proven behavior: it adjusts
    `UNRESOLVED_LANDING_SCAN_COUNTER` only for `BOARD_SCAN_TARGET_PAYLOAD`, may
    clear the two unresolved landing reset bytes when that counter reaches
    zero, and then falls through to `CommitFallingPieceToBoard`.
  - Updated `Yoshi/yoshi.sym`, board-layout notes, fall-timing notes,
    memory-map notes, data-range notes, findings, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name search outside this progress log for `UpdateLandingProgress`
    returned no matches.
  - `git diff --check` passed.

### Phase 5: Game-Turn Parameter Record Structure
- **Status:** completed
- Actions taken:
  - Added `GAME_TURN_PARAM_*` constants for the four-byte
    `GameTurnParamTable` record size, shift, field offsets, record count, and
    always-`$01` unread tail value.
  - Replaced the duplicated `index * 4` instruction pairs in
    `LoadGameTurnPieceDisplayStep` and `InitGameTurnPieceDisplay` with
    `REPT GAME_TURN_PARAM_RECORD_SHIFT`, keeping the assembled bytes unchanged.
  - Documented that the 210 table records provide step timer, display count,
    and fall delay bytes, while the fourth byte is `$01` for every record and
    has no confirmed reader.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - The table parser confirmed 840 bytes / 210 records and tail-byte
    distribution `01:210`.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 357 / 366 items complete.

### Phase 5: Game-Turn Delay Clamp Fragment Labels
- **Status:** completed
- Actions taken:
  - Labeled the two statically unreachable `ld b,$02` fragments immediately
    before `StoreGameTurnPieceDelay` and `StoreInitialGameTurnPieceDelay` as
    `UnreachedGameTurnDelayClamp` and
    `UnreachedInitialGameTurnDelayClamp`.
  - Replaced their raw `$02` operands with `PIECE_FALL_DELAY_MIN`, matching the
    observed minimum delay literal while preserving the emitted bytes.
  - Synced `Yoshi/yoshi.sym` at `00:$19FB` and `00:$1A72`, and documented the
    unreachable branch shape in fall-timing notes and findings.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 358 / 367 items complete.

### Phase 5: Single-Player Game-Over Result Entry Rename
- **Status:** completed
- Actions taken:
  - Renamed `ProcessSinglePlayerOverflowResult` to
    `ProcessSinglePlayerGameOverResult`.
  - Kept the name scoped to the proven path: `DrawLandedPieceAndUpdateColumnTop`
    has just set `RESULT_GAME_OVER_FLAG` after
    `COLUMN_TOP_ROW_OVERFLOW_SENTINEL`, and the 1P branch calls
    `ProcessRoundResultAndEnterRoundEnd` directly rather than queueing a 2P round-result
    packet.
  - Synced `Yoshi/yoshi.sym`, fall-timing notes, findings, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 359 / 368 items complete.

### Phase 5: Result Rank Resolver Rename
- **Status:** completed
- Actions taken:
  - Renamed `CalcRankPosition` to `ResolveResultRankPosition` because the
    routine returns the candidate rank unchanged outside 2P mode, but in 2P
    mode resolves equal local/peer result codes and can clear
    `ROUND_RESULT_CODE` / `RESULT_GAME_OVER_FLAG` on the master side before
    returning `RESULT_RANK_FIRST_PLACE`.
  - Renamed the 2P-only branch from `ResolveTwoPlayerEqualResultCode` to
    `ResolveTwoPlayerEqualResultRank`.
  - Synced `Yoshi/yoshi.sym`, memory-map, link-state, column-blink/rank notes,
    findings, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 360 / 369 items complete.

### Phase 5: Link-Result Confirm Outcome Branch Rename
- **Status:** completed
- Actions taken:
  - Renamed `CheckLinkResultClearFlag` to
    `HandleLinkResultClearConfirmOutcome`.
  - Renamed `CheckLinkResultGameOverFlag` to
    `HandleLinkResultGameOverConfirmOutcome`.
  - Kept the names tied to the proven confirm-screen behavior: these branches
    test `RESULT_CLEAR_FLAG` / `RESULT_GAME_OVER_FLAG`, draw the role status
    strip and the appropriate score-area variant for clear/game-over outcomes,
    or fall through to the animated neutral confirm status strip.
  - Synced `Yoshi/yoshi.sym`, link-state notes, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 361 / 370 items complete.

### Phase 5: Link-Result Packet Outcome Merge Rename
- **Status:** completed
- Actions taken:
  - Renamed `QueueReceivedLinkResult` to `QueueLinkResultPacketOutcome`.
  - Kept the name scoped to the proven behavior: `ProcessLinkResultPacket`
    decodes the bit-7 result packet, defaults the queued result code to
    `ROUND_RESULT_CODE_NONZERO`, optionally clears the peer field-count digits
    and switches to `ROUND_RESULT_CODE_ZERO`, then joins at this label before
    calling `QueueRoundResult`.
  - Synced `Yoshi/yoshi.sym`, link-state notes, findings, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 362 / 371 items complete.

### Phase 5: Link Packet Dispatcher Branch Rename
- **Status:** completed
- Actions taken:
  - Renamed `CheckReceivedLinkFieldCountPacket` to
    `DispatchReceivedLinkFieldCountPacket`.
  - Renamed `CheckReceivedLinkFieldRisePacket` to
    `DispatchReceivedLinkFieldRisePacket`.
  - Kept the names scoped to the dispatcher role: these labels test the bit-5
    field-count packet class and bit-6 field-rise packet class before jumping
    to the actual packet handlers.
  - Synced `Yoshi/yoshi.sym`, link-state notes, findings, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 363 / 372 items complete.

### Phase 5: Link-Result Mark-Limit And Screen-Mode Branch Rename
- **Status:** completed
- Actions taken:
  - Renamed `CheckLinkResultMarkLimit` to
    `SetTerminalLinkResultFlagIfMarkLimitReached`.
  - Renamed `CheckFilledZeroResultMarks` to `DrawZeroResultMarksIfAny`.
  - Renamed `CheckTerminalLinkResultScreen` to
    `DispatchLinkResultScreenMode`.
  - Kept the names tied to the proven flow inside
    `UpdateLinkResultMarksAndScreen`: mark counters are incremented, the
    terminal flag is set when a counter reaches `LINK_RESULT_MARK_LIMIT`, zero
    marks are drawn only when present, and `STATE_TRANSITION` dispatches normal
    confirm versus terminal-result rendering.
  - Synced `Yoshi/yoshi.sym`, link-state notes, findings, and task plan.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 364 / 373 items complete.

### Phase 5: Terminal Link-Result Sound/Clear Tail Rename
- **Status:** completed
- Actions taken:
  - Renamed `UseZeroTerminalLinkResultSound` to
    `LoadZeroTerminalLinkResultSound`.
  - Renamed `PlayTerminalLinkResultSound` to
    `PlayTerminalLinkResultSoundAndClearResultAreas`.
  - Kept the names scoped to the proven terminal result tail: the zero-result
    branch loads `SND_LINK_RESULT_ZERO`, while the shared tail plays the
    selected terminal sound, clears `SERIAL_DONE` / `LINK_SEND`, clears the
    status strip and score-value area, then dispatches to role/result drawing.
  - Synced `Yoshi/yoshi.sym`, link-state notes, findings, task plan, and work
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted stale-name scan found no remaining
    `UseZeroTerminalLinkResultSound` or exact `PlayTerminalLinkResultSound`
    label references.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 365 / 374 items complete.

### Phase 5: Board-Cell Visible Payload Offset
- **Status:** completed
- Actions taken:
  - Renamed `BOARD_CELL_DISPLAY_OFFSET` to
    `BOARD_CELL_VISIBLE_PAYLOAD_OFFSET`.
  - Kept the name tied to the observed read path: `DrawAllColumns` starts at
    `BOARD_DATA + $01`, advances by `BOARD_CELL_STRIDE`, and passes that byte
    to `DrawGridPiece` for each visible row.
  - Left the paired even byte unresolved rather than assigning speculative
    semantics.
  - Updated board-layout, memory-map, findings, task-plan, and work-estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted active source/docs stale-name scan found no remaining
    `BOARD_CELL_DISPLAY_OFFSET` references outside this historical progress
    entry.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 366 / 375 items complete.

### Phase 5: Piece Sprite Object Clear Span Constant
- **Status:** completed
- Actions taken:
  - Added `PIECE_SPRITE_OBJECT_SLOT_COUNT` for the eight logical sprite object
    slots cleared before playfield piece/display setup.
  - Added `PIECE_SPRITE_OBJECT_CLEAR_BYTES` and used it in
    `ClearPieceSpriteObjectSlots` instead of `SPRITE_OBJECT_SLOT_SIZE * $08`.
  - Kept the scope tied to the proven slot span: slots 1-4 are gameplay piece
    slots and slots 5-8 are piece-display/game-over display slots.
  - Updated sprite/OAM notes, piece-display notes, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted clear-span scan found no remaining
    `ld b, SPRITE_OBJECT_SLOT_SIZE * $08` in the active source.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 367 / 376 items complete.

### Phase 5: Field Occupancy Count Decimal Base
- **Status:** completed
- Actions taken:
  - Added `FIELD_OCCUPANCY_COUNT_DECIMAL_BASE` for the `$0A` divisor used by
    `DrawTwoDigitLinkFieldCount`.
  - Replaced the raw `cp $0A` / `sub $0A` in `CountLinkFieldTensDigitLoop`
    with the new constant.
  - Kept the constant scoped to the 2P field-occupancy two-digit renderer:
    the loop repeatedly subtracts ten to build the tens digit before adding
    `FIELD_OCCUPANCY_COUNT_DIGIT_BASE` to both digit tiles.
  - Updated link-state notes, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted field-count scan shows `CountLinkFieldTensDigitLoop` now uses
    `FIELD_OCCUPANCY_COUNT_DECIMAL_BASE` instead of raw `cp/sub $0A`.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 368 / 377 items complete.

### Phase 5: Title Level Preview Digit Coordinate
- **Status:** completed
- Actions taken:
  - Added `TITLE_LEVEL_PREVIEW_DIGITS_COORD` as an alias of
    `PLAYFIELD_LEVEL_DIGITS_A_TYPE_COORD`.
  - Replaced the raw packed coordinate `$0812` in
    `TickTitleLevelDisplayDigits` with the alias.
  - Kept the name scoped to the observed title/preplay redraw path while
    documenting that it shares the row 8 / column 18 coordinate with the
    A-type playfield level HUD.
  - Updated title/menu, egg-counter, memory-map, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted coordinate scan shows the source now uses
    `TITLE_LEVEL_PREVIEW_DIGITS_COORD` at `TickTitleLevelDisplayDigits`; the
    only remaining `$0812` source occurrence is the underlying coordinate
    constant.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 369 / 378 items complete.

### Phase 5: Title UI Fill Tile Bases
- **Status:** completed
- Actions taken:
  - Added `TITLE_FRAME_TOP_RIGHT_CAP_TILE_BASE`,
    `TITLE_FRAME_INNER_TILE_BASE`, `TITLE_FRAME_RIGHT_STRIP_TILE_BASE`,
    `TITLE_MENU_PANEL_TILE_BASE`, `TITLE_LEVEL_STRIP_TILE_BASE`, and
    `TITLE_BOTTOM_RIGHT_PANEL_TILE_BASE`.
  - Replaced the six raw tile-base loads in `InitTitleUI` with those constants.
  - Kept the names scoped to the title setup rectangles already represented by
    `TITLE_*_TOP_LEFT` and `TITLE_*_RECT_SIZE`.
  - Updated title-menu notes, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted title fill scan found no remaining raw `ld a, $80/$C0/$50/$D0/$34/$70`
    loads in `InitTitleUI`.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 370 / 379 items complete.

### Phase 5: Serial Done And Link Queue Constants
- **Status:** completed
- Actions taken:
  - Added `SERIAL_DONE_ACTIVE` for the serial interrupt completion flag value.
  - Added `LINK_SEND_QUEUE_SLOT_COUNT` for the two-slot queued link send ring.
  - Reused the existing `TITLE_LINK_READY_BYTE` in the unassigned-role serial
    interrupt path instead of the raw `$02` comparison.
  - Replaced the `FinishSerialInterrupt` raw active store and
    `AdvanceLinkSendQueueIndex` raw wrap comparison with the new constants.
  - Updated link-state notes, memory-map notes, findings, task-plan, and
    work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Bank 0 scan found no remaining raw `cp $02`; the remaining
    `ld a, $01` sites are outside this touched serial/link-queue scope.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 371 / 380 items complete.

### Phase 5: Title Reset Write-Only Bytes
- **Status:** completed
- Actions taken:
  - Added `TITLE_RESET_UNUSED_HRAM_FLAG` for the sole Yoshi-side `$FF94` write
    in `ResetTitleState`.
  - Added `TITLE_PLAYER_MARKER_UNUSED_DELAY_INITIAL` for the `$05` value stored
    to `TITLE_PLAYER_MARKER_UNUSED_DELAY`.
  - Kept both names low-confidence/write-only: no consumer has been confirmed
    in the current Yoshi source.
  - Updated title-menu notes, confidence notes, memory-map notes, findings,
    task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted `$FF94` scan shows the source now uses
    `TITLE_RESET_UNUSED_HRAM_FLAG` instead of a bare HRAM address.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 372 / 381 items complete.

### Phase 5: Multiply RNG HRAM State
- **Status:** completed
- Actions taken:
  - Added `RNG_STATE` (`$FFBB-$FFBE`), `RNG_WORK` (`$FFBF-$FFC2`), and
    `RNG_MULTIPLIER_LOW_WORK` (`$FFC3`) for the HRAM bytes used only by
    `Multiply`.
  - Added `RNG_MULTIPLIER_HIGH_WORD`, `RNG_MULTIPLIER_LOW_BYTE`, and
    `RNG_INCREMENT_BYTE_0..3` for the constants loaded by the shift/add update.
  - Replaced the remaining raw `$FFBB-$FFC3`, `$0343`, `$FD`, and increment
    byte loads in the live `Multiply` routine.
  - Documented the state/work/update contract in the HRAM memory map and
    findings, without changing the already recovered caller behavior.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted RNG scan shows the live `Multiply` routine now uses the new
    `RNG_*` constants; remaining `$FD` hits are data bytes outside that code
    path.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 373 / 382 items complete.

### Phase 5: Board Adjacent Visible Cell Delta
- **Status:** completed
- Actions taken:
  - Added `BOARD_ADJACENT_VISIBLE_CELL_DELTA` as an alias for the two-byte step
    between adjacent visible cells inside a board column.
  - Applied it where the code moves between visible board cells for landing
    payload staging, B-type initial-board duplicate avoidance, and board-scan
    target probing.
  - Left `BOARD_CELL_STRIDE` in the general draw/drop stride paths, so the new
    alias only marks the adjacent visible-cell semantics.
  - Updated board-layout notes, findings, task-plan, and work-estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted scan shows `BOARD_ADJACENT_VISIBLE_CELL_DELTA` in the expected
    landing, initial-fill, and board-scan target paths.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 374 / 383 items complete.

### Phase 2: BG Map Shadow Copy Enable Flag
- **Status:** completed
- Actions taken:
  - Renamed the HRAM byte at `$FFA5` from `GAME_ACTIVE` to
    `BG_MAP_SHADOW_COPY_ENABLE_FLAG`, matching its only confirmed reader:
    `CopyNextBgMapShadowSlice`.
  - Added `BG_MAP_SHADOW_COPY_ENABLED` for the nonzero value stored by
    `StateInit`, `ProcessMatching`, and the round-complete summary setup.
  - Updated the memory-map and VRAM-copy notes to describe the flag as the
    VBlank BG map shadow copy gate instead of a generic game-active byte.
  - Cleaned up the stale board-layout wording for the newly named
    `BOARD_ADJACENT_VISIBLE_CELL_DELTA`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Stale-name scan for `GAME_ACTIVE` returned no matches in source and
    recovery docs outside this historical progress log.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 375 / 384 items complete.

### Phase 5: Board Scan Reward Score Delta Values
- **Status:** completed
- Actions taken:
  - Added named packed-BCD deltas for the board-scan reward table:
    `BOARD_SCAN_REWARD_SCORE_DELTA_50`,
    `BOARD_SCAN_REWARD_SCORE_DELTA_100`,
    `BOARD_SCAN_REWARD_SCORE_DELTA_200`, and
    `BOARD_SCAN_REWARD_SCORE_DELTA_500`.
  - Replaced the raw high/low byte pairs in `BoardScanRewardScoreDeltaTable`
    with `HIGH()` / `LOW()` expressions over those constants.
  - Updated the data-range and findings notes for the board-scan reward table.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 376 / 385 items complete.

### Phase 4: A-Type Round-Complete Summary Fill And Copy Constants
- **Status:** completed
- Actions taken:
  - Added `TITLE_RESULT_TILES0_COPY_BLOCKS` and
    `TITLE_RESULT_TILES1_COPY_BLOCKS` for the two ROM0 tile-data transfers
    scheduled by `ShowATypeRoundCompleteSummary`.
  - Added `ROUND_COMPLETE_SUMMARY_OBJECT_CLEAR_BYTES` for the sprite-object
    slot clear span before building the summary screen.
  - Added `ROUND_COMPLETE_SUMMARY_BG_FILL_*` constants for the 16x16 shadow
    tilemap fill from `BG_MAP_SHADOW`.
  - Added `EGG_COUNT_DIGIT_MASK`, `ROUND_COMPLETE_SUMMARY_MAX_INDEX`,
    `ROUND_COMPLETE_SUMMARY_MAX_INDEX_TENS_THRESHOLD`,
    `ROUND_COMPLETE_SUMMARY_MID_MESSAGE_TENS_THRESHOLD`, and
    `ROUND_COMPLETE_SUMMARY_BG_COPY_WAIT_FRAMES` for the summary index/message
    selection and three-frame BG shadow copy wait.
  - Updated graphics-load, data-range, memory-map, egg-count, and findings
    notes for the newly named values.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 377 / 386 items complete.

### Phase 4: Round-Complete Reveal Timing And Fill Constants
- **Status:** completed
- Actions taken:
  - Added `ROUND_COMPLETE_PRE_REVEAL_WAIT_FRAMES`,
    `ROUND_COMPLETE_REVEAL_TILE_WAIT_FRAMES`,
    `ROUND_COMPLETE_INPUT_POLL_FRAMES`, and
    `ROUND_COMPLETE_POST_REVEAL_WAIT_FRAMES` for the `ShowRoundComplete`
    wait/poll windows.
  - Added `ROUND_COMPLETE_INPUT_CAPTURED_FLAG` and
    `ROUND_COMPLETE_NO_INPUT_TRANSITION_SENTINEL` for the reveal input capture
    path.
  - Added `ROUND_COMPLETE_REVEAL_THRESHOLD_RECORD_SHIFT` for the
    `RoundCompleteRevealThresholdTable` indexing contract.
  - Added `ROUND_COMPLETE_500_BONUS_BLOCK_*` and
    `ROUND_COMPLETE_REVEAL_*_BLOCK_*` constants for the extra tilemap fills in
    the 500/200/100/50-point reveal branches.
  - Updated the data-range, sprite/OAM, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 378 / 387 items complete.

### Phase 5: Matching Score Bonus Delta Values
- **Status:** completed
- Actions taken:
  - Added `MATCHING_SCORE_BONUS_RECORD_SHIFT` for the two-byte
    `MatchingScoreBonusTable` indexing contract.
  - Added named packed-BCD score deltas from 50 through 1500 points for the
    matching bonus table.
  - Replaced the raw high/low byte pairs in `MatchingScoreBonusTable` with
    `HIGH()` / `LOW()` expressions over those constants.
  - Updated the data-range, findings, task-plan, and estimate notes for the
    newly named values.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 379 / 388 items complete.

### Phase 2: Startup LCDC And VRAM Copy Chunk Constants
- **Status:** completed
- Actions taken:
  - Added `VRAM_COPY_MAX_BLOCKS_PER_VBLANK` for the eight 16-byte block cap used
    by `VRAMCopySetup` and the unreachable secondary setup-shaped fragment.
  - Added `TITLE_INIT_LCDC_FLAGS` for the LCDC value written by `StateInit`
    before the title-init state dispatch.
  - Replaced the corresponding raw immediates in `VRAMCopySetup`,
    `UnusedVRAMCopy2Setup`, and `StateInit`.
  - Updated the VRAM-copy, memory-map, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 380 / 389 items complete.

### Phase 3: Game Type Value Constants
- **Status:** completed
- Actions taken:
  - Added `GAME_TYPE_A` and `GAME_TYPE_B` for the active A/B-style gameplay
    selector stored in `GAME_TYPE`.
  - Replaced the raw B-type value in the `InitGameState` forced-2P setup paths
    with `GAME_TYPE_B`.
  - Updated option-variable, state-machine, memory-map, findings, task-plan, and
    estimate notes for the named game-type values.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 381 / 390 items complete.

### Phase 5: Gameplay Object Active Scan Return Value
- **Status:** completed
- Actions taken:
  - Added `GAMEPLAY_OBJECTS_ACTIVE` for the nonzero return from
    `CheckGameplayObjectSlotsActive`.
  - Replaced the raw `$01` in `ReturnGameplayObjectsActive` with the named
    return value.
  - Updated the sprite/OAM notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 382 / 391 items complete.

### Phase 4: Unused Vertical Tile-Pair Helper Constants
- **Status:** completed
- Actions taken:
  - Added `UNUSED_VERTICAL_TILE_PAIR_SKIP_VALUE` and
    `UNUSED_VERTICAL_TILE_PAIR_TILE_BASE` for the coherent but unreferenced
    helper after the matching/result tables.
  - Replaced the helper's raw `$FF` skip test and `$D2` tile-base addition with
    the named constants.
  - Updated the data-range notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 383 / 392 items complete.

### Phase 4: Draw String Row Terminator
- **Status:** completed
- Actions taken:
  - Added `DRAW_STRING_ROW_END` for the `$FF` row terminator consumed by
    `DrawStringToGrid`.
  - Replaced the raw terminator compare in `CopyStringToGridLoop`.
  - Updated title/menu, option-variable, data-range, findings, task-plan, and
    estimate notes for the named tile-string row terminator.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 384 / 393 items complete.

### Phase 4: Option Text Row Terminators
- **Status:** completed
- Actions taken:
  - Replaced the raw `$FF` terminators in `OptionTextAGame` through
    `OptionTextOff` with `DRAW_STRING_ROW_END`.
  - Updated option/data-range/finding notes and the task-plan estimate for the
    named option text terminators.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 385 / 394 items complete.

### Phase 4: Bank 1 Egg And Title Text Row Terminators
- **Status:** completed
- Actions taken:
  - Replaced raw `$FF` row terminators in `EggTextFrame0..2TileRows` and
    `TitleLabelTextPlayer` / `TitleLabelTextYoshi` with
    `DRAW_STRING_ROW_END`.
  - Updated the Bank 1 tile-string data-range notes, findings, task-plan, and
    estimate notes for the named row terminators.
- Test result:
  - `tools/verify_yoshi_build.sh` passed.
  - `shasum -a 256 Yoshi/yoshi.gb Yoshi/game.gb` reports
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`
    for both ROMs.
  - Raw `$Cxxx`, raw direct branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 386 / 395 items complete.

### Phase 4: One-Player Preplay Header Row Terminators
- **Status:** completed
- Actions taken:
  - Replaced raw `$FF` row terminators in `ResultHeaderText` and
    `ContinueOffText` with `DRAW_STRING_ROW_END`.
  - Updated data-range notes, findings, task-plan, and estimate notes for the
    named 1P preplay header/off text terminators.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the 1P preplay header/off text
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 387 / 396 items complete.

### Phase 4: Preplay Role/Speed/Game-Type/BGM Row Terminators
- **Status:** completed
- Actions taken:
  - Replaced raw `$FF` row terminators in `ScoreHeaderTextRole1`,
    `ScoreHeaderTextRoleOther`, `ResultTextBlock0..2`,
    `RestartTextBlock0..2`, and `BgmMarker0Text..BgmMarkerNoneText` with
    `DRAW_STRING_ROW_END`.
  - Updated data-range notes, findings, task-plan, and estimate notes for the
    named preplay role/speed/game-type/BGM marker row terminators.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the preplay
    role/speed/game-type/BGM marker cleanup and rebuilt `Yoshi/game.gb`
    byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 388 / 397 items complete.

### Phase 4: Piece Preview Row Terminators
- **Status:** completed
- Actions taken:
  - Replaced raw `$FF` row terminators in `PiecePreviewText0..4` and
    `PiecePreviewBlankText` with `DRAW_STRING_ROW_END`.
  - Updated data-range notes, findings, task-plan, and estimate notes for the
    named 2P/1P level-preview text row terminators.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the piece preview row
    terminator cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 389 / 398 items complete.

### Phase 4: Sound Engine FF Constants
- **Status:** completed
- Actions taken:
  - Added scoped constants for sound-engine `$FF` meanings:
    `SOUND_WAVE_RAM_FILL_VALUE`, `SOUND_SEQUENCE_END_COMMAND`,
    `SOUND_VIBRATO_FREQ_MAX`, and `SOUND_REGISTER_PAGE_HI`.
  - Replaced executable raw `$FF` uses in `HandleWaveUpdate`, positive vibrato
    clamp, sequence-end detection, sound-register address construction,
    `SoundEngine` stop-command detection, and `SoundWaveDutyData`.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound-engine `$FF`
    constant cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 390 / 399 items complete.

### Phase 4: Bank 0 FF Sentinel Constant Reuse
- **Status:** completed
- Actions taken:
  - Replaced the raw `$FF` wrap check in
    `UnreachedColumnSpriteAlternateRowFragment` with
    `COLUMN_TOP_ROW_OVERFLOW_SENTINEL`.
  - Replaced the raw `$FF` stored by `WaitFramesSetTransitionOnInput` with
    `ROUND_COMPLETE_NO_INPUT_TRANSITION_SENTINEL`.
  - Updated findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the Bank 0 `$FF` sentinel
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 391 / 400 items complete.

### Phase 5: Visible Board Payload Pattern Records
- **Status:** completed
- Actions taken:
  - Added `BOARD_PAYLOAD_EMPTY`, `BOARD_PAYLOAD_PIECE_1..6`,
    `BOARD_PAYLOAD_SCAN_TRIGGER`, and `BOARD_PAYLOAD_SCAN_TARGET` constants for
    the observed visible board payload range `0..8`.
  - Kept the existing `BOARD_SCAN_TRIGGER_PAYLOAD` and
    `BOARD_SCAN_TARGET_PAYLOAD` names as aliases for the two special scan
    payloads.
  - Renamed `GridPiecePatternPayload0..8` to
    `GridPiecePatternEmptyPayload`, `GridPiecePatternPiece1..6`,
    `GridPiecePatternScanTrigger`, and `GridPiecePatternScanTarget` in source
    and `Yoshi/yoshi.sym`.
  - Updated board-layout, sprite/OAM, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the visible board payload
    pattern-record cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 392 / 401 items complete.

### Phase 5: Drop Collision Helper Labels
- **Status:** completed
- Actions taken:
  - Renamed `CheckCollisionDown` / `CheckCollisionUp` to
    `CheckDropDownCollisionAndNudge` /
    `CheckDropUpCollisionAndNudge`.
  - Renamed `CheckCollisionCore` to
    `CheckDropCollisionAgainstActiveObjects`, and `CheckSpriteOverlap` to
    `CheckDropSpriteOverlap`.
  - Updated the matching `Yoshi/yoshi.sym` labels plus drop-animation findings
    and task/estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the drop collision helper
    label cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 393 / 402 items complete.

### Phase 4/5: Link Result Score-Area Width Labels
- **Status:** completed
- Actions taken:
  - Renamed the two link-result score-area fill helpers from the remaining
    `Variant1/2` names to `FillLinkResultWideScoreArea` and
    `FillLinkResultNarrowScoreArea`.
  - Renamed the confirm-path local branch to
    `FillLinkResultConfirmWideScoreArea`.
  - Renamed the tile/rect constants to
    `LINK_RESULT_SCORE_AREA_WIDE_*` and `LINK_RESULT_SCORE_AREA_NARROW_*`.
  - Updated `Yoshi/yoshi.sym`, link-state notes, findings, task-plan, and
    estimate notes to record the observed 2x7 vs 2x6 score-area distinction.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the link-result score-area
    helper cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted stale-name scan for the old link-result score-area `Variant1/2`
    labels and numbered constants returned no matches after rebuild.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 394 / 403 items complete.

### Phase 3: Invalid GAME_STATE Fallthrough Label
- **Status:** completed
- Actions taken:
  - Renamed the MainLoop out-of-range state branch from
    `ReturnToMainLoopForUnknownState` to `IgnoreInvalidGameStateAndLoop`.
  - Updated `Yoshi/yoshi.sym`, state-machine notes, findings, task-plan, and
    estimate notes to keep the state-dispatch terminology consistent.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the invalid-state fallthrough
    label cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted stale-name scan outside this progress log found no remaining
    `ReturnToMainLoopForUnknownState` references in source, symbols, or current
    recovery notes.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 396 / 405 items complete.

### Phase 5: Architecture Stale Label Sync
- **Status:** completed
- Actions taken:
  - Synced the active `Yoshi/ARCHITECTURE.md` overview with recovered labels
    and data layout. The old placeholder names for gameplay, board, display,
    VBlank, and sound flow are now replaced with current labels such as
    `UpdateGameplayObjectsAndCheckBTypeClear`,
    `UpdateFallingPieceMotionAndLanding`, `GameTurnParamTable`,
    `CopyNextBgMapShadowSlice`, `SoundSequenceStep`, and
    `ProcessSoundNoteCommand`.
  - Corrected the architecture board description from a row-major 4x7 cell
    map to four 16-byte `BOARD_DATA` column blocks with odd-byte visible
    payload cells, and documented `COLUMN_TOP_ROWS` separately.
  - Updated the stale `SPRITE_OBJECT_UPDATE_CONTINUE` source comment and the
    sprite/OAM collision-column note to use
    `UpdateFallingPieceMotionAndLanding` and
    `CheckDropCollisionAgainstActiveObjects`.
  - Updated findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the architecture stale-label
    sync and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted active-doc stale-name scans for the old architecture/source-comment
    labels returned no matches.
  - `git diff --check` passed.
  - Source-recovery checklist progress remains 396 / 405 items complete.

### Phase 4/5: Sound Visual-Update Command Helper
- **Status:** completed
- Actions taken:
  - Renamed the `$F1` sound parser branch from
    `CheckSoundGameStateUpdateCommand` to `CheckSoundVisualUpdateCommand`.
  - Renamed the `01:$7C08` helper from `CheckGameStateUpdate` to
    `ApplySoundVisualUpdateCommand`, matching its behavior: when playing it
    calls `ToggleEggTextAltAnimation`, otherwise it toggles the option BGM
    cursor frame shadow and copies it to the active frame only on the BGM row.
  - Added `SOUND_VISUAL_UPDATE_COMMAND` for the `$F1` parser command check and
    replaced the BGM-row comparison with `MENU_CURSOR_ROW_BGM`.
  - Updated sound-engine, data-range, sprite/OAM, open-question, findings, and
    task-plan notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound visual-update command
    helper cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted stale-name scan found no remaining `CheckGameStateUpdate` or
    `CheckSoundGameStateUpdateCommand` references outside this progress log.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 398 / 406 items complete.

### Phase 5: Board Cell Pair-Lane Semantics
- **Status:** completed
- Actions taken:
  - Added `BOARD_CELL_UNREAD_PAIR_OFFSET` for the even byte in each two-byte
    board row pair and `BOARD_COLUMN_END_SENTINEL_OFFSET` as the source of
    `BOARD_FALL_END_ROW`.
  - Rechecked the live board consumers: `DrawAllColumns`, initial B-type board
    fill, drop-column swap, landing placement, and board-scan target probing
    all use odd visible payload offsets or the `$0F` end sentinel. The even
    byte is only cleared as part of the full `ClearBoardData` span in the live
    source.
  - Updated board-layout, memory-map, open-question, next-work, architecture,
    findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the board-cell pair-lane
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted stale-question scans for the old unresolved paired-even-byte
    wording returned no matches.
  - `git diff --check` passed.
  - Updated the source-recovery checklist progress to 399 / 407 items complete.

### Phase 4/5: Sound Gate-Flag Command Constant
- **Status:** completed
- Actions taken:
  - Added `SOUND_GATE_FLAG_COMMAND` for the `$F8` sound parser command.
  - Added `SOUND_CH_GATE_SUPPRESS_BIT` for bit 0 of `SOUND_CH_GATE_FLAGS`.
  - Replaced the parser compare and the confirmed gate-flag set, reset, and
    check sites while leaving unrelated `SOUND_CH_FLAGS` bit 0 checks alone.
  - Updated sound-engine, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound gate-flag command
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted gate-flag scans show the remaining raw `bit 0, [hl]` in Bank 1 is
    on `SOUND_CH_FLAGS`, not `SOUND_CH_GATE_FLAGS`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 399 / 407 items complete.

### Phase 5: Board Scan Transition Frame-Limit Values
- **Status:** completed
- Actions taken:
  - Added `BOARD_SCAN_TRANSITION_FRAME_LIMIT_1..4` for the values in
    `BoardScanTransitionFrameLimitTable`.
  - Replaced the raw `$01,$02,$02,$02,$03,$03,$04` table bytes with those
    constants.
  - Updated board-layout, data-range, findings, task-plan, and estimate notes
    to describe the selected value as the maximum round-transition sprite frame
    sent by `SendRoundTransitionFrameLoop`.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the table-value cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 401 / 409 items complete.

### Phase 5: Landing/Scan Unresolved Byte Re-Audit
- **Status:** completed
- Actions taken:
  - Rechecked `$C69D/$C6AE/$C6BF/$C6C0` and the
    `UNRESOLVED_LANDING_*` names across the current tree after the board-scan
    table-value cleanup.
  - Confirmed the Yoshi source still only shows the existing write/read pattern:
    `$C69D/$C6AE` are cleared, `$C6BF` is cleared and decremented by
    landing/scan paths, and `$C6C0` is seeded with
    `UNRESOLVED_LANDING_RESET_TIMER_INITIAL` with no confirmed consumer.
  - Left the unresolved names and the open checklist item unchanged. The only
    extra raw `$c6c0` hit is in the unrelated `Pokemon/` sample/source tree, not
    the Yoshi recovery target.
- Test result:
  - No source change was made for this re-audit; the previous byte-identical
    build result still applies to the current code.

### Phase 4/5: Sound Parser Command Byte Constants
- **Status:** completed
- Actions taken:
  - Added named constants for the remaining sound parser command bytes:
    `$FD/$FE`, `$10`, `$20-$2F`, `$B0-$BF`, `$C0-$CF`, `$D0-$DF`,
    `$E0-$EF`, `$E8/$EA/$EB`, `$EC/$ED/$EE/$EF`, `$F0`, `$F1`,
    `$F8`, and `$FC`.
  - Added `SOUND_COMMAND_HIGH_NIBBLE_MASK` and
    `SOUND_COMMAND_LOW_NIBBLE_MASK` for parser-side command-byte splits.
  - Replaced the executable parser compare sites in `bank_001.asm` with the
    named constants while leaving unrelated joypad/vibrato nibble masks raw.
  - Updated sound-engine, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the parser command constant
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted sound-parser scans found no remaining raw `cp $FD/$FE/$10/$20/`
    `$B0/$C0/$D0/$E0/$E8-$F0/$FC` command comparisons.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 403 / 411 items complete.

### Phase 5: Score/Sprite Unused Initial Values
- **Status:** completed
- Actions taken:
  - Added `SCORE_UNUSED_TILE_BASE_INITIAL` for the `$30` seed written to
    `SCORE_UNUSED_TILE_BASE_SOURCE` by `InitBTypeFallTimingAndBoardSeed`.
  - Added `SPRITE_OBJECT_UNUSED_1_INIT_VALUE` for the observed zero byte in
    settings cursor templates, and routed `SETTINGS_CURSOR_INIT_UNUSED_BYTE`
    through that shared value.
  - Kept both unresolved/revisit checklist items open: no independent consumer
    was found for `SCORE_PRESERVED_UNUSED_BYTE`, `SCORE_UNUSED_TILE_BASE_*`, or
    sprite slot `+$01`.
  - Updated memory-map, sprite/OAM, findings, next-work, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the init-value cleanup and
    rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 405 / 413 items complete.

### Phase 4/5: Sound Channel Flag Bit Constants
- **Status:** completed
- Actions taken:
  - Added named bit constants for observed `SOUND_CH_FLAGS` roles:
    frequency carry, `$FD` return pending, note-output gate, vibrato subtract
    phase, pitch-slide active/descending state, and duty-rotate active state.
  - Replaced executable `bit` / `set` / `res` sites over `SOUND_CH_FLAGS` with
    the named bit constants.
  - Replaced the `$E8` command's raw `xor $01` flag toggle with
    `SOUND_CH_FREQ_CARRY_MASK`.
  - Updated sound-engine, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound channel flag cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted `SOUND_CH_FLAGS` scans found no remaining raw bit/set/res or
    `xor $01` flag operations in the executable sound paths.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 406 / 414 items complete.

### Phase 5: Drop/Unused Board Pattern Constants
- **Status:** completed
- Actions taken:
  - Added `DROP_ANIM_ACCEPTED_RETURN_VALUE` for the `$06` returned in `A` after
    `StartDropColumnSwapAnimation` accepts a new drop animation. The current
    caller continues without reading that value, so the name stays scoped to
    the observed return behavior.
  - Added `UNUSED_BOARD_PATTERN_FIRST_COLUMN_INDEX`,
    `UNUSED_BOARD_PATTERN_COLUMN_COUNT`,
    `UNUSED_BOARD_PATTERN_LEADING_CLEAR_BASE`, and
    `UNUSED_BOARD_PATTERN_TAIL_BASE` for the unreferenced
    `UnusedFillBoardDataPattern` fragment.
  - Replaced the fragment's raw `$00/$04/$07/$10` values with the scoped
    constants while keeping it marked `Unused`.
  - Updated board-layout, drop-animation, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the drop/unused-board-pattern
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 406 / 414 items complete.

### Phase 4: Matching Tile-Base Index Scaling
- **Status:** completed
- Actions taken:
  - Added `MATCHING_MIDDLE_OAM_TILE_INDEX_SHIFT` and
    `MATCHING_FINAL_OAM_TILE_INDEX_SHIFT` for the two consumers of
    `MatchingTileBaseIndexTable`.
  - Replaced the raw `sla a` scaling in `ProcessMatching` with those constants:
    middle OAM entries use table entry * 4, and the final pair uses table entry
    * 2.
  - Updated data-range, sprite/OAM, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the matching tile-base scale
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - `git diff --check` passed.
  - Source-recovery checklist progress is 408 / 416 items complete.

### Phase 4/5: Sound Channel Index Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_PRIMARY_WAVE_CHANNEL_INDEX`, `SOUND_CHANNEL3_INDEX`, and
    `SOUND_SECONDARY_WAVE_CHANNEL_INDEX`.
  - Replaced sound parser/setup channel-index comparisons with
    `SOUND_PRIMARY_CHANNEL_COUNT`, `SOUND_LAST_CHANNEL_INDEX`, and the new
    channel-index constants.
  - Left unrelated numeric compares in elapsed-timer and pitch-shift code raw
    because they are not sound channel indexes.
  - Updated sound-engine, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the sound channel-index cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted channel-index scan shows the remaining raw `cp $06` and `cp $07`
    in Bank 1 are elapsed-timer and pitch-shift bounds, not channel-index
    comparisons.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 408 / 416 items complete.

### Phase 4/5: Elapsed Timer Digit Bound Constants
- **Status:** completed
- Actions taken:
  - Added `ELAPSED_TIMER_FRAMES_PER_SECOND`,
    `ELAPSED_TIMER_DECIMAL_DIGIT_LIMIT`,
    `ELAPSED_TIMER_SECONDS_TENS_LIMIT`, `ELAPSED_TIMER_MAX_ONES`, and
    `ELAPSED_TIMER_MAX_SECONDS_TENS`.
  - Replaced the raw frame, digit-rollover, seconds-tens, and clamp immediates
    in `TickElapsedTimerDigits` / `ClampElapsedTimerDigits` with those
    constants.
  - Documented that both elapsed timers use a 60-frame divider and clamp at
    99:59.
  - Updated memory-map, findings, next-work, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the elapsed-timer bound cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted elapsed-timer scan shows the touched `TickElapsedTimerDigits`
    immediate operands now use `ELAPSED_TIMER_*` constants.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 410 / 418 items complete.

### Phase 4/5: Piece Display Selection Threshold Constants
- **Status:** completed
- Actions taken:
  - Added `PIECE_DISPLAY_TIMED_SPECIAL_SECOND_DIGIT_MIN` and
    `PIECE_DISPLAY_TIMED_SPECIAL_OCCUPANCY_LIMIT` for the B-type gated
    `SelectPieceDisplayCode` path.
  - Added named random branch thresholds for the timed-special, first-forced,
    and default selection paths after `Multiply`.
  - Replaced the raw compare values in `SelectPieceDisplayCode` with those
    constants and documented that the names describe branch boundaries, not
    inferred probabilities.
  - Updated piece-display state notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the piece-display threshold
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted piece-display threshold scan found no remaining raw compares for
    the replaced branch boundaries in `Yoshi/bank_000.asm`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 410 / 418 items complete.

### Phase 4/5: Result Record Insert First-Rank Constant
- **Status:** completed
- Actions taken:
  - Replaced the two raw `$01` comparisons in
    `InsertCurrentResultRecordAtRank` with `RESULT_RECORD_FIRST_RANK`.
  - Documented that the extra top-row down-shift is only needed when the current
    record inserts at the first stored rank; lower insertions only shift records
    below the insertion point.
  - Updated result-record notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the result-record insert cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted result-record scan shows `RESULT_RECORD_FIRST_RANK` now covers the
    scan start and both insert down-shift comparisons.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 411 / 419 items complete.

### Phase 2/5: WRAM Clear Mode And Piece-Display Slot Stride Constants
- **Status:** completed
- Actions taken:
  - Added `WRAM_CLEAR_MODE_PRESERVE_RESULT_RECORDS` and
    `WRAM_CLEAR_MODE_FULL` for the startup WRAM clear path.
  - Replaced the startup raw clear-mode values in `Init` /
    `UseFullWRAMClear` with those constants.
  - Replaced the raw `$0010` stride in
    `AddNonForcedPieceDisplayObjectsToUiScratch` with
    `SPRITE_OBJECT_SLOT_SIZE`.
  - Updated memory-map, result-record, piece-display, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the WRAM clear-mode and
    piece-display stride cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted scan shows the startup clear path now uses `WRAM_CLEAR_MODE_*`
    constants and the touched UI-scratch scan now uses `SPRITE_OBJECT_SLOT_SIZE`.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 413 / 421 items complete.

### Phase 4/5: Countdown Digit Buffer Masks
- **Status:** completed
- Actions taken:
  - Added `COUNTDOWN_BLIT_PHASE_TOGGLE_MASK`,
    `COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK`,
    `COUNTDOWN_PATTERN_LOW_NIBBLE_MASK`, and
    `COUNTDOWN_PHASE1_SPILL_PIXEL_MASK`.
  - Replaced the raw phase toggle, high/low nibble masks, and phase-1 spill
    pixel bit in `UpdateCountdownTimer`.
  - Updated countdown digit buffer notes, findings, task-plan, and estimate
    notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the countdown buffer mask cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted countdown scan shows the touched `UpdateCountdownTimer` masks now
    use `COUNTDOWN_*` constants; remaining raw matches are data bytes or other
    routines.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 414 / 422 items complete.

### Phase 4/5: Preplay Label Tile-Row Width Constant
- **Status:** completed
- Actions taken:
  - Added `PREPLAY_LABEL_TILE_ROW_WIDTH` for the four-tile pre-play label
    rows drawn through `DrawSequentialTileRowByCoord`.
  - Replaced the remaining raw `ld b, $04` pre-play label widths in the 1P,
    2P, and detached label paths.
  - Updated option-variable notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the preplay label-width cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted scan shows the touched label paths now use
    `PREPLAY_LABEL_TILE_ROW_WIDTH`; no raw `ld b, $04` remains in Bank 0/1.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 415 / 423 items complete.

### Phase 3/5: Settings Blink Phase Toggle Mask
- **Status:** completed
- Actions taken:
  - Added `SETTINGS_BLINK_PHASE_TOGGLE_MASK` for the shared
    settings/result blink phase at `$C6F1`.
  - Replaced the raw `xor $01` in `TickSettingsBlink` with the new constant.
  - Updated settings blink notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the settings blink mask cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted settings blink scan shows `TickSettingsBlink` now uses
    `SETTINGS_BLINK_PHASE_TOGGLE_MASK`; no raw `xor $01` remains in Bank 0/1.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 416 / 424 items complete.

### Phase 2/5: Bank 1 Joypad Raw Poll Constants
- **Status:** completed
- Actions taken:
  - Replaced Bank 1 `CheckJoypadRaw` raw P1 writes and low-nibble mask with
    `P1F_GET_NONE`, `P1F_GET_BTN`, and `P1_INPUT_BITS_MASK`.
  - Updated memory-map, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the Bank 1 joypad raw poll
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted joypad scan shows `CheckJoypadRaw` now uses the P1 constants;
    remaining raw `and $0f` matches are in unrelated sound-parser code.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 417 / 425 items complete.

### Phase 2/5: Bank 1 Wait-Loop Halt Restoration
- **Status:** completed
- Actions taken:
  - Restored the executable Bank 1 wait-loop raw `$76` bytes as explicit `halt`
    instructions in `WaitVBlankSyncLoop` and
    `WaitJoypadStartOrSelectPressLoop`.
  - Left the remaining `$76` bytes in the Bank 1 music data stream untouched.
  - Updated VRAM/VBlank notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the Bank 1 wait-loop halt cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted halt scan shows the two executable Bank 1 wait loops now use
    `halt`; the remaining `db $76` occurrence is in music sequence data.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 418 / 426 items complete.

### Phase 2/5: Bank 1 Wave-Update Hardware Constants
- **Status:** completed
- Actions taken:
  - Added `SOUND_WAVE_RAM_END_LOW`,
    `SOUND_WAVE_OUTPUT_TERMINAL_BITS`,
    `SOUND_WAVE_OUTPUT_TERMINAL_CLEAR_MASK`,
    `SOUND_WAVE_TRIGGER_VALUE`, and `SOUND_WAVE_UPDATE_END_MARKER`.
  - Replaced `HandleWaveUpdate` raw wave RAM end, channel-3 terminal output,
    trigger, clear-mask, and code-byte end-marker literals with named
    constants.
  - Updated sound-engine notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the Bank 1 wave-update cleanup
    and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted wave-update scan shows the touched literals now use
    `SOUND_WAVE_*` constants.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 419 / 427 items complete.

### Phase 2/5: Bank 1 VBlank Sync And Select Wait Masks
- **Status:** completed
- Actions taken:
  - Added `VBLANK_SYNC_REQUESTED`, `PADF_START_OR_SELECT`, and
    `PADF_SELECT_CLEAR_MASK`.
  - Replaced `WaitVBlank`'s raw sync request value and the static-dead Select
    wait helper's raw Select / Start-or-Select masks with named constants.
  - Labeled the static-dead helper entry at `01:$4BD0` as
    `UnusedWaitSelectThenStartOrSelectPress` and synced `Yoshi/yoshi.sym` to
    the rebuilt `game.sym` address.
  - Updated VBlank/VRAM notes, memory-map notes, findings, task-plan, and
    estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the Bank 1 VBlank sync and
    Select wait-mask cleanup and rebuilt `Yoshi/game.gb` byte-identical to
    `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted Select/VBlank scan shows the touched raw masks now use
    `VBLANK_SYNC_REQUESTED`, `PADF_SELECT`, `PADF_START_OR_SELECT`, and
    `PADF_SELECT_CLEAR_MASK`; remaining raw `$01` matches are outside this
    touched helper.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 420 / 428 items complete.

### Phase 5: Link Result Terminal Flag Clear Constant
- **Status:** completed
- Actions taken:
  - Added `LINK_RESULT_TERMINAL_FLAG_CLEAR` for the `$00` value written to
    `STATE_TRANSITION` at the start of `UpdateLinkResultMarksAndScreen`.
  - Replaced the raw clear value before the mark-limit check, leaving the
    existing `RESULT_FLAG_SET` path for the three-mark terminal case.
  - Updated link-state notes, findings, task-plan, and estimate notes.
- Test result:
  - `tools/verify_yoshi_build.sh` passed after the link-result terminal flag
    cleanup and rebuilt `Yoshi/game.gb` byte-identical to `Yoshi/yoshi.gb`.
  - SHA-256 for both `Yoshi/yoshi.gb` and `Yoshi/game.gb` is
    `970096b7ae14bed8de483f02a1c5ac6ff9259503853c17405eb04bba43687253`.
  - Raw `$Cxxx`, raw direct-branch, generated local-label, and anonymous
    relative-branch scans over Bank 0/1 returned no matches.
  - Duplicate-label and block-overlap audits for `Yoshi/yoshi.sym` returned no
    output, and the rebuilt `Yoshi/game.sym` labels are all covered by
    `Yoshi/yoshi.sym` (`missing 0`).
  - Targeted link-result scan shows `UpdateLinkResultMarksAndScreen` now uses
    `LINK_RESULT_TERMINAL_FLAG_CLEAR`; remaining `STATE_TRANSITION` references
    are other state-machine uses outside this touched path.
  - `git diff --check` passed.
  - Source-recovery checklist progress is 422 / 430 items complete.

## Error Log
| Timestamp | Error | Attempt | Resolution |
|-----------|-------|---------|------------|
| 2026-05-30 | First gameplay/result role rename left stale Bank 1 cross-bank calls to `UpdateGameplayObjectSlotsAndRoundState` and `RefreshField` | 1 | Replaced the Bank 1 call sites with `UpdateGameplayObjectsAndCheckBTypeClear` and `InitResultRecordsIfNeeded`; the verifier returned to byte-identical output. |
| 2026-05-31 | First field animation delta alias pass omitted four bytes from `FieldSideDeltaTable` | 1 | `tools/verify_yoshi_build.sh` reported a byte mismatch; rechecked the original rows, restored the missing zero/positive delta run, and the verifier returned to byte-identical output. |
| 2026-05-31 | First preplay speed text row macro assumed all four left-run tiles were consecutive | 1 | `tools/verify_yoshi_build.sh` reported a byte mismatch; `ResultTextBlock0` row 2 ends with `$9D`, so the macro now takes all four left-run tiles explicitly and the verifier returned to byte-identical output. |
| 2026-05-31 | First 1P preplay header text row macro used `\10+` macro arguments | 1 | `rgbasm` parsed `\10` as `\1` plus `0`; split the long header rows into 8-tile start and 4-/5-tile end macros, then the verifier returned to byte-identical output. |
| 2026-05-30 | First OAM DMA targeted `rg` check over-escaped literal `$` bytes and was rejected | 1 | Re-ran the check as simpler label search plus fixed-string source/symbol scans for the raw payload and stale `.data:a` override. |
| 2026-05-30 | First fall-acceleration high-level threshold constant referenced `ACTIVE_LEVEL_MAX` before that symbol was defined in `constants.inc` | 1 | Changed `PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD` to the local value `$04`, then reran the verifier successfully. |
| 2026-05-28 | Planning files placed in parent directory | 1 | Re-created under `mgbdis/` and removed parent copies. |
| 2026-05-28 | First `VRAM_*` rename changed output bytes at `$4B45/$4B48` | 1 | Corrected `VRAMCopyDMA` destination pointer stores to `$FFB1/$FFB2`; `cmp` returned exit `0`. |
| 2026-05-28 | First `FieldRowDeltaTable` split made ROM0 one byte too large, then produced byte differences | 1 | Rechecked the exact source bytes with `xxd`; corrected the table to exact `00:$230F-$234B` length/content and restored `UpdateFieldTimers` at `00:$234C`. |
| 2026-05-28 | Initial Bank 3 graphics labels for `$5C00` and `$6AB0` landed at repeated-looking rows and changed two `ld hl` operands | 1 | Address-counted `bank_003.asm` by 16-byte tile rows, moved labels to exact source offsets, then restored byte-identical output. |
| 2026-05-28 | First `GameTurnParamTable` conversion omitted the `$04,$02,$08,$01` record at `00:$0C21-$0C24`, shifting the table tail four bytes early | 1 | `cmp -s` failed, `xxd` comparison showed the shifted table bytes, and the missing record was restored; the rebuild returned to byte-identical output. |
| 2026-05-30 | `QueueLinkFieldOccupancyCount` rename left two Bank 1 calls to old `CalcDifficulty` label | 1 | Replaced both Bank 1 call sites with `QueueLinkFieldOccupancyCount` before rerunning the verifier. |
| 2026-05-30 | Temporary ImageMagick tile montage with text labels failed because no default font was available | 1 | Re-ran the tile crop as an unlabeled fixed-order montage and used source/control-flow evidence for the helper names. |
| 2026-05-30 | First VBlank sound/timer local-label cleanup changed one ROM byte by bypassing an intermediate vibrato branch | 1 | Restored the intermediate label and branch before rerunning the verifier; the rebuild returned to byte-identical output. |
| 2026-05-30 | First sound note/output local-label cleanup left stale note-handler and length-register references, then changed two branch bytes by targeting the pre-write `or d` path instead of the original `rNR51` write label | 1 | Replaced the stale references with the new labels and retargeted the two output-mask branches to `WriteSoundChannelOutputMask`; the verifier returned to byte-identical output. |
| 2026-05-30 | First round-end local-label cleanup moved one 1P branch target past the `GAME_TYPE` load and changed the rebuilt ROM | 1 | Moved `HandleSinglePlayerRoundCompleteFlow` before `ld a, [GAME_TYPE]`; the verifier returned to byte-identical output. |
| 2026-05-30 | Broad drop-state inactive replacement touched `Multiply` scratch initialization | 1 | Restored that unrelated write to raw `$00`, then confirmed `DROP_ANIM_STATE_INACTIVE` only appears in the two drop-cascade state-clear sites and the verifier remained byte-identical. |
| 2026-05-30 | Initial link-confirm `@+/@-` cleanup retargeted the backward branches to the routine start/frame store and changed branch-offset bytes | 1 | Used `cmp -l` and `xxd` around `00:$33F7-$344F`; both backward branches target `ContinueLinkConfirmWait` at `00:$33FA`, restoring byte-identical output. |
| 2026-05-30 | First startup `STACK_TOP` constant was defined before `WRAM_START` / `WRAM_SIZE`, so rgbasm reported `undefined symbol WRAM_START` | 1 | Moved `STACK_TOP` below the WRAM base/size definitions, then reran the verifier successfully. |
| 2026-05-30 | A targeted `rg` check used a literal newline in the regex and was rejected | 1 | Re-ran the check with a single-line expression for the remaining `$4A/$E0` loads. |
| 2026-05-30 | A targeted result-record input-mask `rg` check used a literal newline in the regex and was rejected | 1 | Re-ran the check with `awk` to detect only adjacent `JOYPAD_PRESSED` followed by raw `and $0f`; it returned no matches. |
| 2026-05-30 | First option-box constant patch did not match the current `DrawLabel` block context | 1 | Re-read the current line-numbered source and reapplied the same changes as smaller patches. |
| 2026-05-30 | First duplicate-label audit rerun used `=.` instead of `= $.` in the Perl line counter assignment | 1 | Corrected the expression and reran the duplicate-label audit; it returned no output. |

## 5-Question Reboot Check
| Question | Answer |
|----------|--------|
| Where am I? | Phase 2 memory-map, Phase 3 state-machine, and Phase 4 data recovery |
| Where am I going? | More code/data separation, graphics/data maps, sound/music data recovery, gameplay algorithms |
| What's the goal? | Recover the lost Game Boy YOSSY NO TAMAGO source as maintainable, buildable RGBDS assembly |
| What have I learned? | See findings.md |
| What have I done? | Captured baseline facts, verified byte-identical rebuild, added recovery docs/tooling, corrected VRAM transfer variables, named the main `GAME_STATE` values, recovered core option/game-type variables, converted and structured the first Bank 1 sprite data range, converted Bank 0 option UI, score/result/preview text, countdown digit tables, the level fall-delay table, round-complete tables, field delta tables, and ROM0 tail graphics data, restored the Bank 1 sound setup entry at `$55E2` as code, labeled and converted the contiguous Bank 1 sound/music stream from `$569A` through `$7C01` to data, separated the real `$7C02` helper from the surrounding music stream, recovered the `$7C2C-$7FFF` sound index/wave/tail sequence data, named the sound WRAM structure from `$C000-$C0ED` with `SOUND_*` constants, named high-confidence sound IDs from call-site evidence, named the score add/display routine and score WRAM, converted the `$442C` field-column tile table, converted Bank 1 sprite/title tile strings, named title marker blink WRAM, named the next-round, sprite-animation, egg-animation, field-timer, and link-start helpers, removed remaining raw direct call/jump operands from real code paths, added the first rendered graphics evidence pass with Bank 2/3 transfer-start labels, documented the first-pass sprite/OAM object expansion format, traced the first sprite object producer/staging path, and named confirmed sprite object types `$01-$05` |
