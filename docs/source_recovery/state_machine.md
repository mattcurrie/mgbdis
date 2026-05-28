# Main State Machine

This document tracks the recovered meaning of `GAME_STATE` (`$FFC7`). The main
dispatcher is in `Yoshi/bank_000.asm` at `MainLoop`.

## State Values

| Value | Constant | MainLoop behavior | Evidence |
|-------|----------|-------------------|----------|
| `$00` | `GAME_STATE_TITLE_INIT` | Loads title graphics from Bank 2, initializes title UI, plays sound `$30`, then advances. | `MainLoop` zero case copies `$4000/$6000` to VRAM, calls `InitTitleUI`, then `AdvanceState`. |
| `$01` | `GAME_STATE_TITLE_MENU` | Polls title/player-selection input. | MainLoop state 1 calls current label `InitGameVars`; that routine clears gameplay scratch state and calls Bank 1 `ProcessTitleInput` and `ProcessOptionInput`. |
| `$02` | `GAME_STATE_PLAY_SETUP` | Loads playfield graphics, initializes gameplay field, starts BGM, then advances. | MainLoop state 2 calls `LoadGameTiles`, `FillOAMGameTile`, `ApplyGameSettings`/`PlaySound`, `InitPlayfield`, then `AdvanceState`. |
| `$03` | `GAME_STATE_PLAYING` | Runs regular gameplay frame update. | MainLoop state 3 calls `HandlePause` and Bank 1 `GameMainUpdate`; serial/timer helpers explicitly check for `$03`. |
| `$04` | `GAME_STATE_ROUND_END` | Handles result/high-score/continue flow. | MainLoop state 4 calls `HandleRoundEnd`; `ProcessNewHighScore` stores `$04` before returning to the loop. |
| `$05` | `GAME_STATE_PREPLAY_LOOP` | Runs the settings/start-wait loop before entering play setup. | MainLoop state 5 calls current label `OptionsScreen`; that label dispatches to `ProcessRoundEndLoop` in 1P and `UpdateGameLoop` in 2P. The 1P path handles menu cursor/input and stores `$02` on Start. |
| `$06` | `GAME_STATE_PREPLAY_INIT` | Loads settings/start-wait graphics and prepares the pre-play loop, then enters state `$05`. | Bank 1 `ProcessOptionInput` stores `$06`; MainLoop state 6 copies Bank 2 graphics and calls `StartGameplay`, then stores `$05`. |

## Observed Transitions

| From | To | Trigger / Code Path |
|------|----|---------------------|
| `$00` title init | `$01` title menu | `AdvanceState` after title graphics/UI setup. |
| `$01` title menu | `$06` pre-play init | Bank 1 `ProcessOptionInput` after Start/link-selection path. |
| `$06` pre-play init | `$05` pre-play loop | MainLoop state 6 after settings/start-wait graphics/setup. |
| `$05` pre-play loop | `$02` play setup | 1P `ProcessRoundEndLoop` Start path after `InitGameState`; 2P path needs further tracing. |
| `$02` play setup | `$03` playing | `AdvanceState` after playfield/game board setup. |
| `$03` playing | `$02` play setup | 2P restart/reconfigure path in `UpdateGameLoop`, or continue path in `ProcessRoundEndLoop`. |
| `$03`/round result helper | `$04` round end | `ProcessNewHighScore` after high-score/result setup. |
| `$04` round end | `$03` playing | `HandleRoundEnd` paths that prepare the next round and resume play. |
| `$04` round end | `$00` title init | `HandleRoundEnd` return-to-title path. |

## Naming Notes

- The existing label `InitGameVars` is misleading in state `$01`: it is called every title-menu frame and delegates to title/option input handlers. A future behavior-preserving rename candidate is `RunTitleMenu`.
- State `$05` and `$06` are pre-play states. In 1P they cover the option/settings menu; in 2P state `$05` dispatches through `UpdateGameLoop`, so the link-ready/start path still needs a dedicated trace.
- State `$04` is broader than a simple "round end": it includes high-score/result display timing and can return to title or resume play depending on result and input.
