# Initial WRAM/HRAM Recovery Notes

This document tracks memory-map recovery for `Yoshi/yoshi.gb`. Confidence levels:

- **High**: direct code behavior and existing labels agree.
- **Medium**: strong contextual evidence, but name may still be refined.
- **Low**: useful hypothesis only.

## Cartridge / ROM Banking

| Address / Value | Name | Confidence | Evidence |
|-----------------|------|------------|----------|
| `$2100` | `MBC1_ROM_BANK_REG` | High | Every observed ROM bank switch writes here; the ROM header declares cartridge type `$01` (MBC1). |
| `$01` | `ROM_BANK_MAIN_CODE` | High | Restored after graphics loads; contains VBlank, sprites, sound, and normal cross-bank routines. |
| `$02` | `ROM_BANK_GRAPHICS_0` | High | Selected for Bank 2 title/game/common/two-player graphics copies. |
| `$03` | `ROM_BANK_GRAPHICS_1` | High | Selected for Bank 3 match/result/high-score graphics copies. |

## Existing Named HRAM

These definitions already exist in `Yoshi/constants.inc` and are referenced by the disassembly.

| Address | Name | Confidence | Evidence |
|---------|------|------------|----------|
| `$FF80` | `OAM_DMA_HRAM` | High | `SetupOAMDMA` copies the OAM DMA routine to this HRAM address; `VBlankHandler` calls it after `VRAMCopyDMA`. |
| `$FF8A` | `ANIM_FRAME` | Medium | Heavy use in matching/result/title animation paths; may be a generic temporary animation counter rather than one semantic variable. |
| `$FF8B` | `STATE_TRANSITION` | Medium | Used as a transition/phase flag in matching, BG update, next-piece drawing, round transitions. |
| `$FF8C` | `ANIM_SUBFRAME` | Medium | Used near result/link/title animation paths. |
| `$FF8D` | `TEXT_FADE` | Medium | Used by title text fade and other UI fade/timing code. |
| `$FF93` | `SCREEN_STATE` | Medium | Used in scan/timer/result/menu code; exact semantics still need validation. |
| `$FF97-$FF9A` | `PIECE_DISPLAY_SLOT_ORDER` | High | Four slot indices initialized to `0,1,2,3`, shuffled by `ShufflePieceDisplaySlotOrder`, and used by `DisplayResults` to choose which `PIECE_DISPLAY_STATES` entry to write. |
| `$FF9B` | `WAVE_UPDATE` | High | Checked by VBlank before wave RAM update. |
| `$FF9C` | `SCX_SHADOW` | High | Copied to `rSCX` in VBlank. |
| `$FFA0` | `JOYPAD_RAW` | High | Written by `ReadJoypadButtons`; consumed as input state. |
| `$FFA1` | `JOYPAD_PRESSED` | High | Written by `ReadJoypadButtons`; read by menu/game/pause handlers. |
| `$FFA2` | `JOYPAD_HELD` | High | Written by `ReadJoypadButtons`; read by joypad helpers. |
| `$FFA5` | `GAME_ACTIVE` | Medium | Used by game field/VBlank related code; exact role needs validation. |
| `$FFAE` | `VRAM_COPY_BLOCKS` | High | `VRAMCopySetup` writes a length/count byte here; `VRAMCopyDMA` reads it as a loop count and transfers 16 bytes per iteration. |
| `$FFAF-$FFB0` | `VRAM_SRC_LO`/`VRAM_SRC_HI` | High | `VRAMCopySetup` stores the source pointer here; `VRAMCopyDMA` loads it into SP before popping 16-byte chunks. |
| `$FFB1-$FFB2` | `VRAM_DST_LO`/`VRAM_DST_HI` | High | `VRAMCopySetup` stores destination pointer here; `VRAMCopyDMA` updates this pair after the copy loop. |
| `$FFB3-$FFB7` | `UNUSED_VRAM_COPY2_*` | High | Written only by the unreachable `UnusedVRAMCopy2Setup` fragment at `00:$0244`; no VBlank/DMA consumer reads this secondary slot. |
| `$FFC4` | `VBLANK_BUSY` | Medium | Used by VBlank sync/wait logic. |
| `$FFC5` | `VBLANK_SYNC` | Medium | Used by `WaitVBlank`/VBlank synchronization. |
| `$FFC7` | `GAME_STATE` | High | Main state machine index in `MainLoop`. |
| `$FFC8` | `SERIAL_DONE` | High | Serial transfer completion flag. |
| `$FFE0` | `SERIAL_TEMP` | Low | Existing name; current reference scan shows mostly temporary writes and needs validation. |

## Existing Named WRAM

| Address | Name | Confidence | Evidence |
|---------|------|------------|----------|
| `$C4A0-$C607` | `BG_MAP_SHADOW` | High | `FillGameTilemap` / `FillTitleTilemap` fill `$0168` bytes, `CalcTilemapAddress` maps row/column pairs as `$C4A0 + row * 20 + column`, and Bank 1 copies chunks of this buffer to BG map VRAM `$9C00-$9DDF`. |
| `$C61C` | `LCD_REDRAW` | High | Read by `UpdateSprites`, written around LCD/VRAM refresh paths. |
| `$C61D-$C61F` | `SCORE_BCD_LOW` / `SCORE_BCD_MID` / `SCORE_BCD_HIGH` | High | Bank 1 `AddScore` adds an `HL` BCD score delta with `daa`, caps overflow at `99999`, and stores the packed BCD accumulator here. |
| `$C621-$C625` | `SCORE_DIGITS` | High | `AddScore` unpacks the BCD score into five low-nibble display digits; Bank 0 `UpdateLevel` reads five bytes from this range when drawing the score. |
| `$C62A` | `BOARD_DATA` | Low | Existing constant, but direct scan did not see the symbol; board may be addressed via nearby pointers/indexed offsets. |
| `$C66A-$C66D` | `COLUMN_TOP_ROWS` | High | Four per-column row/fall-target bytes. Seeded from level setup, indexed by `PIECE_ROTATION`, used by drawing and fall logic, and swapped by `AnimateDropping`. |
| `$C66E` | `SPRITE_OBJECT_DELAY_RELOAD` | High | Initialized to `1` by `ResetTitleState` and copied into `SPRITE_OBJECT_STAGING + SPRITE_OBJECT_DELAY_COUNTER` when `UpdateSpriteObject` advances a waiting gameplay object slot. |
| `$C66F` | `DROP_CURSOR_ANIM_ACTIVE` | High | Set when `CheckMatch` accepts a drop input, drives `InitGameState2` cursor-frame animation, and gates `DisplayScore` timing. |
| `$C670` | `DROP_CURSOR_FRAME_TIMER` | High | Decremented and reloaded by `InitGameState2` before advancing `SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_FRAME`. |
| `$C671` | `GAME_TYPE` | High | Set from `OPTION_GAME_TYPE` in 1P and forced to 1 in 2P; selects A/B-style gameplay/layout/result behavior, not 1P/2P. |
| `$C673-$C677` | `PIECE_DISPLAY_CODE_POOL` | High | Five code bytes initialized to `1..5`; the first four are shuffled by `ShufflePieceDisplayCodePool`, and `DisplayResults` indexes this pool before `ProcessMenuSelection`. |
| `$C68F` | `PIECE_FALL_POS` | Medium | Used by falling/update/scan routines. |
| `$C691` | `PIECE_ROTATION` | Medium | Used by piece movement/update routines. |
| `$C69D` | Unresolved landing/reset byte | Low | Cleared by `DropPiece` and again by `UpdateLandingProgress` when the unresolved `$C6BF` counter reaches zero; no consumer has been confirmed. |
| `$C697` | `PIECE_DISPLAY_REMAINING` | Medium | `ProcessMenuLoop` stores the same value as `PIECE_DISPLAY_COUNT`; `MovePieceLeft` and `ShowResults` decrement it, but no independent read has been confirmed. |
| `$C698` | `PIECE_DISPLAY_COUNT` | High | Loaded from the second byte of the current `GameTurnParamTable` row or forced to `2` during gameplay setup; callers pass it into `DisplayResults`. |
| `$C699` | `COLUMN_TOP_ROW_SEED` | High | Loaded from `LevelCountTable` or forced to `$0F`; `SeedColumnTopRows` copies it into all four `COLUMN_TOP_ROWS` entries, and `ProcessInputTitle` uses it to size the initial board-fill loop. |
| `$C6A2` | `ROUND_COMPLETE_PARAM_INDEX` | High | `UpdateTimer` saves the pre-remap `SCREEN_STATE` here before applying `RoundCompleteStateRemapTable`; the round-complete tail doubles it to index `RoundCompleteDelayParamTable` before calling `AddScore`. |
| `$C6A3-$C6A6` | `PIECE_DISPLAY_STATES` | High | Four display-state bytes built by `DisplayResults` and scanned by `HandleGameOver` / `AnimateGameOver` to emit piece sprite objects in slots 1-4. |
| `$C696` | `PIECE_FALL_TIMER` | High | Decremented/reloaded by `DisplayScore`; `UpdateMatchState` returns without moving the staged piece while it is nonzero. |
| `$C6A7` | `PIECE_FALL_DELAY` | High | Reload value for `PIECE_FALL_TIMER`, initialized from `ProcessFalling` or `GAME_TURN_DELAY` and periodically lowered by `DisplaySpeed` down to `PIECE_FALL_DELAY_MIN`. |
| `$C6A9` | `GAME_TURN_TABLE_INDEX` | High | `DrawMenuCursor` seeds this from `LevelThresholds`; `ProcessMenuLoop` increments it and indexes `GameTurnParamTable + index * 4`. |
| `$C6AA` | `GAME_TURN_STEP_TIMER` | High | Reloaded from the first byte of the current `GameTurnParamTable` record, decremented by `UpdateMenuCursor`, and advances the table when it reaches zero. |
| `$C6AB` | `RESULT_FLOW_ACTIVE` | High | Set by `ProcessNewHighScore` and `QueueRoundResult`, cleared by `DropPiece` and the return-to-title path, and read by Bank 1 `SetupGameBG` to suppress normal field background setup during result/high-score flow. |
| `$C6AC` | `GAME_TURN_DELAY` | High | Loaded from the third byte of the current `GameTurnParamTable` record, optionally halved by `ACTIVE_SPEED`, then copied into `PIECE_FALL_DELAY` / `PIECE_FALL_TIMER`. |
| `$C6AD` | `PIECE_DISPLAY_FORCE_ALL_STATES_FLAG` | High | Set by a timer-gated `ProcessMenuSelection` branch; `ApplyAllForcedPieceDisplayStates` rewrites every nonzero display-state entry to `PIECE_DISPLAY_FORCED_STATE`, and `DisplayResults` clears the flag afterward. |
| `$C6AE` | Unresolved landing/reset byte | Low | Same confirmed write pattern as `$C69D`: cleared by `DropPiece` and again by `UpdateLandingProgress` when `$C6BF` reaches zero; no consumer has been confirmed. |
| `$C6AF` | `PIECE_DISPLAY_BLINK_TIMER` | High | Decremented each `GameMainUpdate`; when it expires, it reloads to `$20` and toggles bit `$10` in the sprite frame byte for active piece-display sprite objects, except frames `$07/$08`. |
| `$C6B0` | `PIECE_FALL_ACCEL_TIMER` | High | Countdown reloaded with `$0A`; when it expires, `DisplaySpeed` lowers `PIECE_FALL_DELAY` by one until the minimum delay is reached. |
| `$C6B1` | `MENU_CURSOR` | High | Indexes the four option bytes from `$C6B2-$C6B5`. |
| `$C6B2` | `OPTION_GAME_TYPE` | High | Selected game type; copied into `GAME_TYPE` by `InitGameState`. |
| `$C6B3` | `OPTION_LEVEL` | High | Selected starting level; copied into `ACTIVE_LEVEL` and `PROGRESSION_LEVEL`. |
| `$C6B4` | `OPTION_SPEED` | High | Selected drop speed; copied into `ACTIVE_SPEED`. |
| `$C6B5` | `OPTION_BGM` | High | Selected BGM; mapped to sound commands by `ApplyGameSettings`. |
| `$C6B6` | `TWO_PLAYER_FLAG` | High | Highest-frequency named WRAM flag; used across title, options, gameplay, link, and drawing paths. |
| `$C6B7` | `ACTIVE_LEVEL` | High | Active level copied from options or link settings; used by thresholds and result/high-score paths. |
| `$C6B8` | `ACTIVE_SPEED` | High | Active drop speed copied from options or link settings; used by timing and display paths. |
| `$C6B9` | `LINK_RECV` | High | Link receive byte used by serial/link logic. |
| `$C6BA` | `LINK_SEND` | High | Link send byte used by serial/link logic. |
| `$C6BB` | `LINK_ROLE` | High | Read throughout 2P/link paths; values appear to distinguish no link/master/slave. |
| `$C6BC` | `TITLE_PLAYER_MARKER_TIMER` | High | `DisplayNextPiece` decrements this timer before toggling the title 1P/2P selection marker. |
| `$C6BE` | `TITLE_PLAYER_MARKER_PHASE` | High | Selects whether `DisplayNextPiece` draws the top or bottom title selection marker tiles. |
| `$C6BF` | Unresolved landing/scan counter | Medium | Cleared by `DropPiece`, decremented by `ScanBoard` after `UpdateTimer`, decremented by two by `UpdateLandingProgress` for staged payload `$08`, and used to decide when to clear `$C69D/$C6AE`. |
| `$C6C0` | Unresolved write-only landing/reset byte | Low | `DropPiece` writes `$14` here; no consumer has been confirmed. |
| `$C6C1` | `BGM_PREVIEW_TIMER` | Medium | Set during BGM option changes and decremented by `TickBgmPreviewTimer`. |
| `$C6C2` | `BGM_PREVIEW_PERIOD` | Low | Stores BGM-specific values during preview setup; direct consumer still needs confirmation. |
| `$C6C3-$C6C6` | `FIELD_ANIM_SLOT_*_CURSOR` | High | Four table cursors for sprite object slots 11, 10, 13, and 12. `StepFieldAnimSlot*` routines index `FieldSideDeltaTable` / `FieldRowDeltaTable` until sentinel `$10`, then reset the matching cursor. |
| `$C6C7-$C6CA` | `FIELD_ANIM_SLOT_*_ACTIVE` | High | Active flags for sprite object slots 12, 11, 10, and 13. Round-complete paths set all four flags; each slot update routine tests its flag and clears it when its delta table terminates. |
| `$C6CB-$C6CE` | `FIELD_COLUMN_TIMERS` | High | Four timers tied to logical sprite object slots 10-13. `UpdateBoard` reloads one timer by `PIECE_ROTATION`; `UpdateFieldTimers` decrements them and clears the matching `$C2xx` slot when a timer reaches zero. |
| `$C6CF` | `SPRITE_ANIM_FRAME` | Medium | Used by init/update animation paths; copied into result/history records. |
| `$C6D0` | `SPRITE_ANIM_STATE` | Medium | Used with `SPRITE_ANIM_FRAME`; copied into result/history records. |
| `$C6D1` | `SPRITE_ANIM_TICK_COUNTER` | High | `TitleInputHandler` increments this divider and advances `SPRITE_ANIM_FRAME` / `SPRITE_ANIM_STATE` every 10 ticks; setup paths clear it through `ClearSpriteAnimTickCounter`. |
| `$C6D2` | `EGG_COUNT_RESERVED` | Low | Cleared together with the egg counter in init/reset paths, but no direct read has been confirmed. |
| `$C6D3-$C6D5` | `EGG_COUNT_ONES` / `EGG_COUNT_TENS` / `EGG_COUNT_HUNDREDS` | High | `IncrementEggCounter` updates these as decimal digits capped at 999; `DrawEggCount` renders ones/tens as tile `$40+digit`, and result setup copies hundreds/tens/ones into `CURRENT_RESULT_DETAIL_DIGITS`. |
| `$C6D6-$C6DA` | `ROUND_TIMER_DIGITS` / `ROUND_TIMER_FRAME_COUNTER` | High | `UpdateElapsedTimers` calls `TickElapsedTimerDigits` to tick this four-digit elapsed timer through a 60-frame divider; `FieldUpdate14` draws it on the playfield, `FieldUpdate15` clears it for a new round, and B-type title/result logic reads the leading digits. |
| `$C6DB-$C6DF` | `TOTAL_TIMER_DIGITS` / `TOTAL_TIMER_FRAME_COUNTER` | High | `UpdateElapsedTimers` calls `TickElapsedTimerDigits` to tick this second four-digit elapsed timer through its own 60-frame divider; `FieldUpdate16` clears it at playfield init and B-type result setup copies the four digits into the result record. |
| `$C6E0` | `FIELD_COLUMN_TILE_PATTERN_INDEX` | High | Initialized to `1` with the player cursor, decremented/incremented as left/right input moves the cursor, and shifted by `LoadGameBGTiles` to select a 16-byte `FieldColumnTilePatternTable` record. |
| `$C6E1` | `BGM_INDEX` | Medium | Used when selecting BGM/sound. |
| `$C6E2` | `PROGRESSION_LEVEL` | High | Initialized from option/link level, incremented by `AdvanceSpriteAnimFrame` / `AnimFrameData`, capped at `$13` for `LevelFallDelayTable`, and passed to `ProcessMatching` in the B-type continuation path. |
| `$C6E4-$C6E5` | `ROUND_TIMER_STOPPED` / `TOTAL_TIMER_STOPPED` | High | Completion and result setup set both flags to stop elapsed-time updates; next-round setup clears only the round timer, while new playfield setup clears both timers and both stop flags. |
| `$C6E6` | `LINK_FIELD_EVENT_PAYLOAD` | Medium | Falling-piece code builds a bit-6 field-event payload here, then the round-complete path copies it into `LINK_SEND_QUEUE_0`. |
| `$C6E7` | `LINK_SEND_DROP_INPUT_LOCK` | High | `Send2PData` sets this while calling `CheckMatch` inside its link-send wait loop; `CheckMatch` uses it to suppress starting a new drop while still allowing movement/input polling. |
| `$C6E8-$C6EA` | `EGG_TEXT_PULSE_FRAME` / `EGG_TEXT_PULSE_TIMER` / `EGG_TEXT_PULSE_STEPS` | High | Seeded when `IncrementEggCounter` wraps the ones digit; `UpdateEggTextAnimation` uses these bytes to alternate `AnimateSprite` frames 1 and 2 with a `$28` frame delay. |
| `$C6EB-$C6EC` | `LINK_2P_SELECTED_LEVEL` / `LINK_2P_SELECTED_SPEED` | High | The 2P option loop edits these two bytes, `UpdateGameField` packs them into `LINK_SEND`, and 2P setup copies them into `ACTIVE_LEVEL` / `ACTIVE_SPEED`. |
| `$C6F0` | `LINK_SETTINGS_CURSOR` | High | 2P pre-play cursor. Up/down clamp it to level row `0` or speed row `1`; left/right index `LINK_2P_SELECTED_LEVEL` / `LINK_2P_SELECTED_SPEED`. |
| `$C6F1` | `SETTINGS_BLINK_PHASE` | High | `TickSettingsBlink` toggles this bit every `$0F` frames. Selected 2P setting/result-option rows use it to alternate between normal text and blank text. |
| `$C6F2` | `SETTINGS_BLINK_TIMER` | High | Reloaded with `$0F` on setup/input; decremented by `TickSettingsBlink` before toggling `SETTINGS_BLINK_PHASE`. |
| `$C6F3-$C6F4` | `EGG_TEXT_ALT_ANIM_ACTIVE` / `EGG_TEXT_ALT_ANIM_PHASE` | High | The tens-digit wrap path enables this continuous `AnimateSprite` frame 1/2 alternation; `RunTitleMenu` clears both bytes, round/playfield setup clears the phase byte, and the playing-state VBlank check toggles the phase. |
| `$C6F5-$C6F6` | `ROUND_COMPLETE_TILE_BASE_X` / `ROUND_COMPLETE_TILE_BASE_Y` | High | `ShowRoundComplete` stores each round-complete tile-group base X (`$10/$30/$50/$70`) and fixed base Y `$80` here; `ProcessRoundComplete` copies the pair into sprite object slots 10-13. |
| `$C6F7` | `PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG` | High | Set by a timer-gated `ProcessMenuSelection` branch; `ApplyFirstForcedPieceDisplayState` consumes it and rewrites the first nonzero display-state entry to `PIECE_DISPLAY_FORCED_STATE`. |
| `$C6F8` | `PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG` | High | One-shot flag set by `DisplayResults` for display counts of three or more; the next `ProcessMenuSelection` call clears it and skips the timer-gated special-selection path. |
| `$C6FA` | `LINK_PENDING_FIELD_RISE` | Medium | Incoming bit-6 link events add to this byte; `SelectMenuItem` consumes it in chunks while adjusting `SCREEN_STATE`. |
| `$C6FB` | `LINK_STAGING_BYTE` | Low | Cleared with link state; direct read still unconfirmed. |
| `$C6FC-$C6FD` | `LINK_SEND_QUEUE_0` / `LINK_SEND_QUEUE_1` | High | `TimerTickCore` alternates between these two bytes, sends the selected byte through `LINK_SEND`, then clears that queue slot. |
| `$C6FE` | `LINK_SEND_QUEUE_INDEX` | High | Alternates between 0 and 1 to select the next link send queue slot. |
| `$C6FF-$C700` | `LINK_RECV_LEVEL` / `LINK_RECV_SPEED` | High | `UpdateGameField` unpacks peer level/speed nibbles from `LINK_RECV`; preview/result paths read these values for peer display. |
| `$C701-$C702` | `LINK_RESULT_NONZERO_MARKS` / `LINK_RESULT_ZERO_MARKS` | High | 2P result counters cleared by `RunTitleMenu`; `CheckHighScoreTable` increments the nonzero or zero counter, sets the terminal overlay when either reaches three, and draws the two mark rows from `$C4F3` upward and `$C4FF` downward. |
| `$C703` | `RESULT_CLEAR_FLAG` | High | B-type board-clear detection sets this when all four `COLUMN_TOP_ROWS` reach `$0F`; result display checks it before drawing the clear/win message and setup paths clear it for a new round/playfield. |
| `$C704` | `RESULT_GAME_OVER_FLAG` | High | Set when the falling-piece placement overflows the local field; result/link display checks it for the game-over/loss message, and tie-resolution code can clear it before queueing the final result. |
| `$C705` | `ROUND_RESULT_PENDING` | High | `QueueRoundResult` sets this flag after storing the result code; Bank 1 `Check2PGameState` consumes it to call `ProcessNewHighScore`, and `Send2PData` uses it to skip normal inner-frame updates once result flow is queued. |
| `$C706` | `ROUND_RESULT_CODE` | High | `QueueRoundResult` stores the argument that Bank 1 later passes to `ProcessNewHighScore`; title/start-next-round setup clears it with `ROUND_RESULT_PENDING`. |
| `$C707` | `PAUSE_FLAG` | High | Pause/unpause and 2P pause paths. |
| `$C708` | `LINK_PEER_RESULT_CODE` | High | `UpdateDifficulty` receives the peer's bit-7 result packet, clears bit 7, and stores the peer result code here; `CalcRankPosition` compares it with the local result code during 2P result resolution. |
| `$C709-$C729` | `A_TYPE_RESULT_RECORDS` | High | Three 11-byte score/egg records. `RefreshField` initializes their heads to `$FF`, `ClearField` compares/inserts the staged `CURRENT_RESULT_RECORD`, and result setup renders this table for A-type. |
| `$C72A-$C74A` | `B_TYPE_RESULT_RECORDS` | High | Three 11-byte score/time records with the same insertion/rendering path selected when `GAME_TYPE` is nonzero. |
| `$C74B-$C755` | `CURRENT_RESULT_RECORD` | High | Staged result record built from `SCORE_DIGITS`, sprite animation state/frame, and either egg digits or `TOTAL_TIMER_DIGITS` before being inserted into the A/B record table. |
| `$C756` | `RESULT_RECORDS_INIT_FLAG` | High | Prevents repeated `$FF` seeding of the result record heads. |
| `$C757-$C75A` | `WRAM_PERSIST_MAGIC` | High | Startup magic `$C7,$8A,$29,$36`; when valid, the WRAM clear loop skips `$C709-$C75A` so result records survive reset. |
| `$C75B-$C75C` | `ROUND_END_WAIT_TIMER` | High | Seeded with `$003C` by `ProcessNewHighScore`; decremented by the 2P round-end path before continuing. |
| `$C75D` | `DROP_ANIM_ACTIVE` | High | `StartDropAnim` sets it to `$FF`, `AnimateDropping` and `CheckMatch` gate on it, and the cascade completion path clears it. |
| `$C75E` | `DROP_ANIM_FRAME_TIMER` | High | Decremented by `AnimateDropping` and reloaded before advancing drop cascade states. |
| `$C761` | `DROP_ANIM_COLUMN` | High | Stores the selected column index for collision checks, grid-position calculation, and final `$C66A` column-state swap. |
| `$C762` | `DROP_ANIM_GRID_ROW_TMP` | Low | Written by `CalcGridPosition` as local scratch; no independent direct read has been confirmed. |
| `$C764/$C774` | `DROP_ANIM_DOWN_STATES` / `DROP_ANIM_UP_STATES` | High | Two seven-entry, two-byte-stride cascade state arrays advanced by `AnimateDropDown` and `AnimateDropUp`. |
| `$C7A4` | `COLUMN_BLINK_GLOBAL_TIMER` | High | `UpdateColumnBlinkState` increments this timer and wraps it at `$30` before scanning the four column blink slots. |
| `$C7A5-$C7A8` | `COLUMN_BLINK_SLOT_TIMERS` | High | Four per-slot blink counters walked in parallel with `COLUMN_BLINK_SLOT_FLAGS`; a nonzero counter increments until `$10`, then toggles the slot frame. |
| `$C7A9-$C7AC` | `COLUMN_BLINK_SLOT_FLAGS` | High | Four active/frame bytes. `InitBlinkState` sets them to 1, title init clears them, and `UpdateColumnBlinkState` toggles active bytes between 1 and 2 before calling `DrawColumnSprite`. |
| `$C7AD` | `RESULT_RANK_POSITION` | High | `ProcessNewHighScore` stores the rank/high-score position returned by `CalcRankPosition`; `DrawScoreRanking` and B-game round-end branching read it. |
| `$C7AE-$C7CD` | `COUNTDOWN_DIGIT_BUFFER_0..3` | High | Four 8-byte digit bitmap staging buffers. `UpdateCountdownTimer` builds them from `SCORE_BCD_*` and `CountdownDigitPatternTable`; `RandomNext` blits pairs to VRAM `$9020` / `$9120`. |
| `$C7CE` | `COUNTDOWN_BLIT_TIMER` | High | Nonzero while countdown digit buffers still need VRAM blits. `LoadAnimData` seeds it with 2, `RandomNext` decrements it, and result setup clears it. |
| `$C7CF` | `COUNTDOWN_BLIT_PHASE` | High | Toggled by `UpdateCountdownTimer`; selects which digit-buffer pair `RandomNext` copies to VRAM. |

## High-Priority Unnamed Regions

These addresses appear often enough to deserve early recovery. Some are real structures; some are code/data disassembly artifacts.

| Address/Range | Evidence | Initial hypothesis |
|---------------|----------|--------------------|
| `$C000-$C0ED` | Many references from Bank 1 sound routines and tables; now named as `SOUND_*` constants. | Sound engine state, channel sequence pointers, timers, pitch slide state, tempo, and wave selectors. Continue refining medium-confidence field names. |
| `$C200-$C2FF` | `SPRITE_OBJECTS`; 16 logical sprite object slots, `$10` bytes each. | `UpdateSprites` scans this page in `$10`-byte steps and expands active slots into shadow OAM; `UpdateSpriteObject` stages gameplay slots 1-4 through `$C68C-$C695`. |
| `$C300-$C3FF` | Sprite/field-adjacent work area, not yet fully mapped. | Some references may still be from real field/UI state or from older data artifacts; needs separate trace. |
| `$C400-$C49F` | `SHADOW_OAM`; 40 hardware OAM entries. | `ClearOAM` clears `$A0` bytes; HRAM OAM DMA copies page `$C4` to hardware OAM; `UpdateSprites` appends entries here. The adjacent `$C4A0-$C607` range is `BG_MAP_SHADOW`, not OAM. |
| `$C4A0-$C607` | Now named `BG_MAP_SHADOW`; used by result/title/2P display routines as tilemap destinations before Bank 1 copies chunks to VRAM. | BG map shadow, not OAM. Continue refining named offsets inside the buffer. |

## Code/Data Misclassification Candidates

The reference scan intentionally reports address-like operands even when they occur in suspicious code. These are high-value cleanup targets because they can hide real tables.

| Area | Evidence | Action |
|------|----------|--------|
| `Yoshi/bank_000.asm` `00:$0B8D-$0ED2` | `DrawMenuCursor` and `ProcessMenuLoop` index `$0B8D + GAME_TURN_TABLE_INDEX * 4`; the head was previously decoded as bogus instructions while the tail was already `db`. | Converted the fake-code head to `GameTurnParamTable` rows and named the local index/timer/delay bytes. |
| `Yoshi/bank_000.asm` `00:$117C-$11EF` | Matching/result code copies `$117C/$1184/$1194` to shadow OAM, indexes `$119C` as `STATE_TRANSITION * 2` score pairs, and indexes `$11D4` as a tile-base table. | Converted to three OAM templates, `MatchingScoreBonusTable`, and `MatchingTileBaseIndexTable`; preserved the real-looking `$11F0` helper as code. |
| `Yoshi/bank_001.asm` `01:$40A0-$42F4` | `UpdateSprites` indexes `$40A0` as a pointer table; the range before `UpdateAnimFrame` was previously decoded as bogus instructions. | Converted to `SpriteUpdatePointerTable`, object frame tables, tile-id lists, and layout triples in source. |
| `Yoshi/bank_001.asm` `01:$442C-$445B` | `LoadGameBGTiles` indexes `$442C` as six 16-byte records before real code at `$445C`. | Converted to `FieldColumnTilePatternTable`; `$445C` is now the real `StartNextRound` entry. |
| `Yoshi/bank_001.asm` `01:$462B-$465C` | `AnimateSprite` selects `$462B`, `$4639`, or `$464B`, then calls `DrawStringToGrid` four times. | Converted to `SpriteAnimTextFrame0..2` tile-string blocks; `$465D` remains the real `DrawEggCount` entry. |
| `Yoshi/bank_001.asm` `01:$46ED-$46FE` | `DrawTitleLabels` draws `$46ED` and `$46F6` through `DrawStringToGrid`. | Converted to `TitleLabelTextPlayer` and `TitleLabelTextYoshi`; `$46FF` remains the real `ProcessTitleInput` entry. |
| `Yoshi/bank_001.asm` `01:$55E2-$5668` | `SoundEngine` and `SoundLookupIndex` jump to `$55E2`; the bytes form a coherent sound setup routine. | Converted to `StartSoundSequence` code. |
| `Yoshi/bank_001.asm` `01:$5669-$5699` | Sound routines directly index `$566A`, `$5672`, `$567A`, and `$5682`; `$569A` is a sequence entry target, not pitch-table data. | Split into small sound support tables. |
| `Yoshi/bank_001.asm` `01:$569A-$5FE2` | Already represented as `db`, but was mostly one large unlabeled sequence block. | Added first-pass internal pointer-target labels. |
| `Yoshi/bank_001.asm` `01:$5FE3-$7C01` | Previously contained many instruction-looking bytes and fake labels. | Converted to `MusicSequenceData_*` blocks while preserving the real `$7C02` helper. |
| `Yoshi/bank_000.asm` `00:$22CC-$234B` | Field drawing routines index `$22CC` and `$230F` with `GetArrayElement`; `$234C` is called from Bank 0 and Bank 1 as code. | Converted to `FieldSideDeltaTable` and `FieldRowDeltaTable`; restored `UpdateFieldTimers` at `$234C`. |
| `Yoshi/bank_000.asm` `00:$3839-$3FFF` | `ShowWinScreen` / result setup copies `$3839` and `$3D39` to VRAM via `VRAMCopySetup`; the area is dense 2bpp tile data and produced fake jumps when decoded as code. | Converted to `TitleResultTileData0`, `TitleResultTileData1`, and `Bank0TailGraphicsData`. |

## Immediate Next Steps

1. Refine medium-confidence `SOUND_CH_*` slide/tempo/envelope names by decoding more sequence examples.
2. Trace `GAME_STATE` writes and assign concrete state names.
3. Decode the visual meaning of each Bank 2/3 graphics load range.
4. Continue refining the shared settings/pre-play cursor drawing routines.
5. Continue code/data separation for remaining small fake-code islands.
