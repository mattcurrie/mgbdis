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
| `$C61C` | `LCD_REDRAW` | High | Read by `UpdateSprites`, written around LCD/VRAM refresh paths. |
| `$C61D-$C61F` | `SCORE_BCD_LOW` / `SCORE_BCD_MID` / `SCORE_BCD_HIGH` | High | Bank 1 `AddScore` adds an `HL` BCD score delta with `daa`, caps overflow at `99999`, and stores the packed BCD accumulator here. |
| `$C621-$C625` | `SCORE_DIGITS` | High | `AddScore` unpacks the BCD score into five low-nibble display digits; Bank 0 `UpdateLevel` reads five bytes from this range when drawing the score. |
| `$C62A` | `BOARD_DATA` | Low | Existing constant, but direct scan did not see the symbol; board may be addressed via nearby pointers/indexed offsets. |
| `$C66A-$C66D` | `COLUMN_TOP_ROWS` | High | Four per-column row/fall-target bytes. Seeded from level setup, indexed by `PIECE_ROTATION`, used by drawing and fall logic, and swapped by `AnimateDropping`. |
| `$C66F` | `DROP_CURSOR_ANIM_ACTIVE` | High | Set when `CheckMatch` accepts a drop input, drives `InitGameState2` cursor-frame animation, and gates `DisplayScore` timing. |
| `$C670` | `DROP_CURSOR_FRAME_TIMER` | High | Decremented and reloaded by `InitGameState2` before advancing `SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_FRAME`. |
| `$C671` | `GAME_TYPE` | High | Set from `OPTION_GAME_TYPE` in 1P and forced to 1 in 2P; selects A/B-style gameplay/layout/result behavior, not 1P/2P. |
| `$C673-$C677` | `PIECE_DISPLAY_CODE_POOL` | High | Five code bytes initialized to `1..5`; the first four are shuffled by `ShufflePieceDisplayCodePool`, and `DisplayResults` indexes this pool before `ProcessMenuSelection`. |
| `$C68F` | `PIECE_FALL_POS` | Medium | Used by falling/update/scan routines. |
| `$C691` | `PIECE_ROTATION` | Medium | Used by piece movement/update routines. |
| `$C6A3-$C6A6` | `PIECE_DISPLAY_STATES` | High | Four display-state bytes built by `DisplayResults` and scanned by `HandleGameOver` / `AnimateGameOver` to emit piece sprite objects in slots 1-4. |
| `$C696` | `PIECE_FALL_TIMER` | High | Decremented/reloaded by `DisplayScore`; `UpdateMatchState` returns without moving the staged piece while it is nonzero. |
| `$C6A7` | `PIECE_FALL_DELAY` | High | Reload value for `PIECE_FALL_TIMER`, initialized from `ProcessFalling` or `GAME_TURN_DELAY` and periodically lowered by `DisplaySpeed` down to `PIECE_FALL_DELAY_MIN`. |
| `$C6A9` | `GAME_TURN_TABLE_INDEX` | High | `DrawMenuCursor` seeds this from `LevelThresholds`; `ProcessMenuLoop` increments it and indexes `GameTurnParamTable + index * 4`. |
| `$C6AA` | `GAME_TURN_STEP_TIMER` | High | Reloaded from the first byte of the current `GameTurnParamTable` record, decremented by `UpdateMenuCursor`, and advances the table when it reaches zero. |
| `$C6AC` | `GAME_TURN_DELAY` | High | Loaded from the third byte of the current `GameTurnParamTable` record, optionally halved by `ACTIVE_SPEED`, then copied into `PIECE_FALL_DELAY` / `PIECE_FALL_TIMER`. |
| `$C6B1` | `MENU_CURSOR` | High | Indexes the four option bytes from `$C6B2-$C6B5`. |
| `$C6B2` | `OPTION_GAME_TYPE` | High | Selected game type; copied into `GAME_TYPE` by `InitGameState`. |
| `$C6B3` | `OPTION_LEVEL` | High | Selected starting level; copied into `ACTIVE_LEVEL`. |
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
| `$C6C1` | `BGM_PREVIEW_TIMER` | Medium | Set during BGM option changes and decremented by `TickBgmPreviewTimer`. |
| `$C6C2` | `BGM_PREVIEW_PERIOD` | Low | Stores BGM-specific values during preview setup; direct consumer still needs confirmation. |
| `$C6C3-$C6C6` | `FIELD_ANIM_SLOT_*_CURSOR` | High | Four table cursors for sprite object slots 11, 10, 13, and 12. `StepFieldAnimSlot*` routines index `FieldSideDeltaTable` / `FieldRowDeltaTable` until sentinel `$10`, then reset the matching cursor. |
| `$C6C7-$C6CA` | `FIELD_ANIM_SLOT_*_ACTIVE` | High | Active flags for sprite object slots 12, 11, 10, and 13. Round-complete paths set all four flags; each slot update routine tests its flag and clears it when its delta table terminates. |
| `$C6CB-$C6CE` | `FIELD_COLUMN_TIMERS` | High | Four timers tied to logical sprite object slots 10-13. `UpdateBoard` reloads one timer by `PIECE_ROTATION`; `UpdateFieldTimers` decrements them and clears the matching `$C2xx` slot when a timer reaches zero. |
| `$C6CF` | `SPRITE_ANIM_FRAME` | Medium | Used by init/update animation paths; copied into result/history records. |
| `$C6D0` | `SPRITE_ANIM_STATE` | Medium | Used with `SPRITE_ANIM_FRAME`; copied into result/history records. |
| `$C6D1` | `SPRITE_ANIM_TICK_COUNTER` | High | `TitleInputHandler` increments this divider and advances `SPRITE_ANIM_FRAME` / `SPRITE_ANIM_STATE` every 10 ticks; setup paths clear it through `ClearSpriteAnimTickCounter`. |
| `$C6D2` | `EGG_COUNT_RESERVED` | Low | Cleared together with the egg counter in init/reset paths, but no direct read has been confirmed. |
| `$C6D3-$C6D5` | `EGG_COUNT_ONES` / `EGG_COUNT_TENS` / `EGG_COUNT_HUNDREDS` | High | `IncrementEggCounter` updates these as decimal digits capped at 999; `DrawEggCount` renders ones/tens as tile `$40+digit`, and result setup copies hundreds/tens/ones into `$C752-$C754`. |
| `$C6E1` | `BGM_INDEX` | Medium | Used when selecting BGM/sound. |
| `$C6E6` | `LINK_FIELD_EVENT_PAYLOAD` | Medium | Falling-piece code builds a bit-6 field-event payload here, then the round-complete path copies it into `LINK_SEND_QUEUE_0`. |
| `$C6EB-$C6EC` | `LINK_2P_SELECTED_LEVEL` / `LINK_2P_SELECTED_SPEED` | High | The 2P option loop edits these two bytes, `UpdateGameField` packs them into `LINK_SEND`, and 2P setup copies them into `ACTIVE_LEVEL` / `ACTIVE_SPEED`. |
| `$C6F0` | `LINK_SETTINGS_CURSOR` | High | 2P pre-play cursor. Up/down clamp it to level row `0` or speed row `1`; left/right index `LINK_2P_SELECTED_LEVEL` / `LINK_2P_SELECTED_SPEED`. |
| `$C6F1` | `SETTINGS_BLINK_PHASE` | High | `TickSettingsBlink` toggles this bit every `$0F` frames. Selected 2P setting/result-option rows use it to alternate between normal text and blank text. |
| `$C6F2` | `SETTINGS_BLINK_TIMER` | High | Reloaded with `$0F` on setup/input; decremented by `TickSettingsBlink` before toggling `SETTINGS_BLINK_PHASE`. |
| `$C6FA` | `LINK_PENDING_FIELD_RISE` | Medium | Incoming bit-6 link events add to this byte; `SelectMenuItem` consumes it in chunks while adjusting `SCREEN_STATE`. |
| `$C6FB` | `LINK_STAGING_BYTE` | Low | Cleared with link state; direct read still unconfirmed. |
| `$C6FC-$C6FD` | `LINK_SEND_QUEUE_0` / `LINK_SEND_QUEUE_1` | High | `TimerTickCore` alternates between these two bytes, sends the selected byte through `LINK_SEND`, then clears that queue slot. |
| `$C6FE` | `LINK_SEND_QUEUE_INDEX` | High | Alternates between 0 and 1 to select the next link send queue slot. |
| `$C6FF-$C700` | `LINK_RECV_LEVEL` / `LINK_RECV_SPEED` | High | `UpdateGameField` unpacks peer level/speed nibbles from `LINK_RECV`; preview/result paths read these values for peer display. |
| `$C707` | `PAUSE_FLAG` | High | Pause/unpause and 2P pause paths. |
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
| `$C400-$C49F` | `SHADOW_OAM`; 40 hardware OAM entries. | `ClearOAM` clears `$A0` bytes; HRAM OAM DMA copies page `$C4` to hardware OAM; `UpdateSprites` appends entries here. |
| `$C4A0-$C5FF` | Used by result/title/2P display routines as data destinations. | UI/OAM/meta-sprite buffers and display work area. |

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
