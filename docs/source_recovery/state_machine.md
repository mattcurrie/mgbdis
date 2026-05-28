# Main State Machine

This document tracks the recovered meaning of `GAME_STATE` (`$FFC7`). The main
dispatcher is in `Yoshi/bank_000.asm` at `MainLoop`.

## State Values

| Value | Constant | MainLoop behavior | Evidence |
|-------|----------|-------------------|----------|
| `$00` | `GAME_STATE_TITLE_INIT` | Loads title graphics from Bank 2, initializes title UI, plays sound `$30`, then advances. | `MainLoop` zero case copies `$4000/$6000` to VRAM, calls `InitTitleUI`, then `AdvanceState`. |
| `$01` | `GAME_STATE_TITLE_MENU` | Polls title/player-selection input. | MainLoop state 1 calls `RunTitleMenu`; that routine clears gameplay/result scratch state and calls Bank 1 `ProcessTitleInput` and `ProcessOptionInput`. |
| `$02` | `GAME_STATE_PLAY_SETUP` | Loads playfield graphics, initializes gameplay field, starts BGM, then advances. | MainLoop state 2 calls `LoadGameTiles`, `FillOAMGameTile`, `ApplyGameSettings`/`PlaySound`, `InitPlayfield`, then `AdvanceState`. |
| `$03` | `GAME_STATE_PLAYING` | Runs regular gameplay frame update. | MainLoop state 3 calls `HandlePause` and Bank 1 `GameMainUpdate`; serial/timer helpers explicitly check for `$03`. |
| `$04` | `GAME_STATE_ROUND_END` | Handles result/high-score/continue flow. | MainLoop state 4 calls `HandleRoundEnd`; `ProcessNewHighScore` stores `$04` before returning to the loop. |
| `$05` | `GAME_STATE_PREPLAY_LOOP` | Runs the settings/start-wait loop before entering play setup. | MainLoop state 5 calls `RunPreplayLoop`; that label dispatches to `Run1PPreplayLoop` in 1P and `Run2PPreplayLoop` in 2P. The 1P path handles menu cursor/input and stores `$02` on Start; the 2P path waits for the link-start handshake byte `$55`. |
| `$06` | `GAME_STATE_PREPLAY_INIT` | Loads settings/start-wait graphics and prepares the pre-play loop, then enters state `$05`. | Bank 1 `ProcessOptionInput` stores `$06`; MainLoop state 6 copies Bank 2 graphics and calls `StartGameplay`, then stores `$05`. In 1P, `StartGameplay` calls `InitPreplayBlinkTimer` and `Init1PPreplayScreen`; in 2P it starts the link BGM and draws the two-player status screen. |

## Observed Transitions

| From | To | Trigger / Code Path |
|------|----|---------------------|
| `$00` title init | `$01` title menu | `AdvanceState` after title graphics/UI setup. |
| `$01` title menu | `$06` pre-play init | Bank 1 `ProcessOptionInput` after Start/link-selection path. |
| `$06` pre-play init | `$05` pre-play loop | MainLoop state 6 after settings/start-wait graphics/setup. |
| `$05` pre-play loop | `$02` play setup | 1P `Run1PPreplayLoop` Start path after `InitGameState`; 2P `Run2PPreplayLoop` master Start button or peer `$55` link handshake path after `InitGameState`. |
| `$02` play setup | `$03` playing | `AdvanceState` after playfield/game board setup. |
| `$03`/round result helper | `$04` round end | `ProcessNewHighScore` after high-score/result setup. |
| `$04` round end | `$03` playing | `HandleRoundEnd` paths that prepare the next round and resume play. |
| `$04` round end | `$00` title init | `HandleRoundEnd` return-to-title path. |

## Naming Notes

- State `$01` is a live title-menu loop, not a one-shot initializer. `RunTitleMenu` clears per-menu scratch bytes each frame, updates the 1P/2P selection, and watches for the Start/link path into pre-play init.
- State `$05` and `$06` are pre-play states. In 1P they cover the option/settings menu; in 2P state `$05` dispatches through `Run2PPreplayLoop`, which edits the two link settings and waits until the master sends or the peer receives `$55` before entering play setup.
- State `$04` is broader than a simple "round end": it includes high-score/result display timing and can return to title or resume play depending on result and input.
