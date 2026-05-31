# Main State Machine

This document tracks the recovered meaning of `GAME_STATE` (`$FFC7`). The main
dispatcher is in `Yoshi/bank_000.asm` at `MainLoop`.

The MainLoop state chain now has behavior-named dispatch labels:
`DispatchTitleMenuState`, `DispatchPlaySetupState`, `DispatchPlayingState`,
`DispatchRoundEndState`, `DispatchPreplayLoopState`, and
`DispatchPreplayInitState`. Values beyond the recovered `$00-$06` state range
fall through `IgnoreInvalidGameStateAndLoop`.

## State Values

| Value | Constant | MainLoop behavior | Evidence |
|-------|----------|-------------------|----------|
| `$00` | `GAME_STATE_TITLE_INIT` | Loads title graphics from Bank 2, initializes title UI, plays sound `$30`, then advances. | `MainLoop` zero case copies `$4000/$6000` to VRAM, calls `InitTitleUI`, then `AdvanceState`. |
| `$01` | `GAME_STATE_TITLE_MENU` | Polls title/player-selection input. | MainLoop state 1 calls `RunTitleMenu`; that routine clears gameplay/result scratch state and calls Bank 1 `ProcessTitleInput` and `ProcessOptionInput`. |
| `$02` | `GAME_STATE_PLAY_SETUP` | Loads playfield graphics, initializes gameplay field, starts BGM, then advances. | MainLoop state 2 calls `LoadGameTiles`, `FillGameTilemap`, `ApplyGameSettings`/`PlaySound`, `InitPlayfield`, then `AdvanceState`. |
| `$03` | `GAME_STATE_PLAYING` | Runs regular gameplay frame update. | MainLoop state 3 calls `HandlePause` and Bank 1 `RunGameplayFrame`; serial/timer helpers explicitly check for `$03`. |
| `$04` | `GAME_STATE_ROUND_END` | Handles result/result-record/continue flow. | MainLoop state 4 calls `HandleRoundEnd`; `ProcessRoundResultAndEnterRoundEnd` stores `$04` before returning to the loop. |
| `$05` | `GAME_STATE_PREPLAY_LOOP` | Runs the settings/start-wait loop before entering play setup. | MainLoop state 5 calls `RunPreplayLoop`; that label dispatches to `Run1PPreplayLoop` in 1P and `Run2PPreplayLoop` in 2P. The 1P path handles menu cursor/input through `Handle1PPreplayNonStartInput` and stores `$02` on Start; the 2P path handles setting input through `Handle2PPreplayNonStartInput` and enters play setup through the `LINK_CONFIRM_BYTE` handshake path ending at `Enter2PPreplayPlaySetup`. |
| `$06` | `GAME_STATE_PREPLAY_INIT` | Loads settings/start-wait graphics and prepares the pre-play loop, then enters state `$05`. | Bank 1 `ProcessOptionInput` stores `$06`; MainLoop state 6 copies Bank 2 graphics and calls `StartGameplay`, then stores `$05`. In 1P, `StartGameplay` calls `InitPreplayBlinkTimer` and `Init1PPreplayScreen`; in 2P, `InitTwoPlayerPreplayScreen` chooses the link-role sound, calls `Init2PPreplayBlinkTimer`, and draws the two-player status screen through `Draw2PPreplayScreen`. |

## Observed Transitions

| From | To | Trigger / Code Path |
|------|----|---------------------|
| `$00` title init | `$01` title menu | `AdvanceState` after title graphics/UI setup. |
| `$01` title menu | `$06` pre-play init | Bank 1 `ProcessOptionInput` after Start/link-selection path. |
| `$06` pre-play init | `$05` pre-play loop | MainLoop state 6 after settings/start-wait graphics/setup. |
| `$05` pre-play loop | `$02` play setup | 1P `Run1PPreplayLoop` Start path after `InitGameState`; 2P `Run2PPreplayLoop` master Start button or peer `LINK_CONFIRM_BYTE` link handshake path after `InitGameState`. |
| `$02` play setup | `$03` playing | `AdvanceState` after playfield/game board setup. |
| `$03`/round result helper | `$04` round end | `ProcessRoundResultAndEnterRoundEnd` after round-result setup. |
| `$04` round end | `$03` playing | `HandleRoundEnd` paths that prepare the next round and resume play. |
| `$04` round end | `$00` title init | `HandleRoundEnd` return-to-title path. |

## Trace Coverage Audit

- Current `GAME_STATE` writers are limited to the named state constants
  `$00-$06`, plus the `AdvanceState` increment path from title init and play
  setup.
- No distinct demo/attract-loop state has been recovered in the current source.
  The idle title path remains `GAME_STATE_TITLE_MENU`, which calls
  `RunTitleMenu` until player input or link handshake enters pre-play setup.
- The options path is the state `$01 -> $06 -> $05` route:
  `ProcessOptionInput` enters pre-play init, then the pre-play loop handles
  settings/start input through either `Run1PPreplayLoop` or `Run2PPreplayLoop`.
- Gameplay is confined to `GAME_STATE_PLAYING`, whose main-loop branch calls
  `HandlePause` and `RunGameplayFrame`; VBlank-side timer/link helpers also check
  this state before applying gameplay-only updates.
- Round-end/result flow is confined to `GAME_STATE_ROUND_END` and helper paths
  that either resume `GAME_STATE_PLAYING` for the next round or return to
  `GAME_STATE_TITLE_INIT`.
- The 2P path has no separate top-level state value: it branches inside the
  title/pre-play, gameplay, and round-end handlers through `TWO_PLAYER_FLAG`,
  `LINK_ROLE`, and link-packet state.

## Naming Notes

- State `$01` is a live title-menu loop, not a one-shot initializer. `RunTitleMenu` clears per-menu scratch bytes each frame, updates the 1P/2P selection, and watches for the Start/link path into pre-play init.
- State `$05` and `$06` are pre-play states. In 1P they cover the option/settings menu; in 2P state `$05` dispatches through `Run2PPreplayLoop`, which edits the two link settings and waits until the master sends or the peer receives `LINK_CONFIRM_BYTE` before entering play setup.
- `InitGameState` now names the 1P and 2P setup branches as
  `InitSinglePlayerLevelSpeedSettings` and
  `InitTwoPlayerLevelSpeedSettings`. The 1P branch copies
  `OPTION_GAME_TYPE`, `OPTION_LEVEL`, and `OPTION_SPEED`; the 2P branch forces
  `GAME_TYPE_B` and copies the negotiated link level/speed.
- State `$04` is broader than a simple "round end": it includes result/result-record display timing and can return to title or resume play depending on result and input.
- `RESULT_FLOW_ACTIVE` (`$C6AB`) is raised by the round-result setup paths and prevents Bank 1 `DrawGameplayBgTopRowIfNoResultFlow` from redrawing the normal playfield background until the flow is cleared back to `RESULT_FLOW_INACTIVE`.
