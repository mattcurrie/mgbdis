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
| `$FF9B` | `WAVE_UPDATE` | High | Checked by VBlank before wave RAM update. |
| `$FF9C` | `SCX_SHADOW` | High | Copied to `rSCX` in VBlank. |
| `$FFA0` | `JOYPAD_RAW` | High | Written by `ReadJoypadButtons`; consumed as input state. |
| `$FFA1` | `JOYPAD_PRESSED` | High | Written by `ReadJoypadButtons`; read by menu/game/pause handlers. |
| `$FFA2` | `JOYPAD_HELD` | High | Written by `ReadJoypadButtons`; read by joypad helpers. |
| `$FFA5` | `GAME_ACTIVE` | Medium | Used by game field/VBlank related code; exact role needs validation. |
| `$FFAE` | `VRAM_COPY_BLOCKS` | High | `VRAMCopySetup` writes a length/count byte here; `VRAMCopyDMA` reads it as a loop count and transfers 16 bytes per iteration. |
| `$FFAF-$FFB0` | `VRAM_SRC_LO`/`VRAM_SRC_HI` | High | `VRAMCopySetup` stores the source pointer here; `VRAMCopyDMA` loads it into SP before popping 16-byte chunks. |
| `$FFB1-$FFB2` | `VRAM_DST_LO`/`VRAM_DST_HI` | High | `VRAMCopySetup` stores destination pointer here; `VRAMCopyDMA` updates this pair after the copy loop. |
| `$FFB3` | `VRAM_COPY2_BLOCKS` | Low | Written by a second setup block; likely alternate/secondary count, but the exact consumer path is not yet confirmed. |
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
| `$C671` | `GAME_TYPE` | High | Set from `OPTION_GAME_TYPE` in 1P and forced to 1 in 2P; selects A/B-style gameplay/layout/result behavior, not 1P/2P. |
| `$C68F` | `PIECE_FALL_POS` | Medium | Used by falling/update/scan routines. |
| `$C691` | `PIECE_ROTATION` | Medium | Used by piece movement/update routines. |
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
| `$C6C1` | `BGM_PREVIEW_TIMER` | Medium | Set during BGM option changes and decremented by `TickBgmPreviewTimer`. |
| `$C6C2` | `BGM_PREVIEW_PERIOD` | Low | Stores BGM-specific values during preview setup; direct consumer still needs confirmation. |
| `$C6C3-$C6C6` | field delta cursors | Medium | `DrawField2`, `DrawField4`, and `DrawFieldRow` use these as indexes into `FieldSideDeltaTable` / `FieldRowDeltaTable`; exact variable names are still pending. |
| `$C6C7-$C6CA` | field redraw flags | Medium | `DrawField1`, `DrawField3`, and `DrawFieldBorder` test these flags before animating field edge/row updates, then clear them at table terminators. |
| `$C6CB-$C6CE` | field redraw timers | Medium | `UpdateFieldTimers` decrements four bytes and clears corresponding C2xx display rows through `ResetTimers` when a timer reaches zero. |
| `$C6CF` | `SPRITE_ANIM_FRAME` | Medium | Used by init/update animation paths; exact scope needs validation. |
| `$C6D0` | `SPRITE_ANIM_STATE` | Medium | Used with `SPRITE_ANIM_FRAME`. |
| `$C6E1` | `BGM_INDEX` | Medium | Used when selecting BGM/sound. |
| `$C6F0` | `MENU_SELECT` | Medium | Used in result/stat/next-piece UI paths; may need a more specific name. |
| `$C6F1` | `GAME_MODE_FLAG` | Medium | Used in game loop, score/bonus/result drawing; exact semantics need validation. |
| `$C707` | `PAUSE_FLAG` | High | Pause/unpause and 2P pause paths. |

## High-Priority Unnamed Regions

These addresses appear often enough to deserve early recovery. Some are real structures; some are code/data disassembly artifacts.

| Address/Range | Evidence | Initial hypothesis |
|---------------|----------|--------------------|
| `$C000-$C0ED` | Many references from Bank 1 sound routines and tables; now named as `SOUND_*` constants. | Sound engine state, channel sequence pointers, timers, pitch slide state, tempo, and wave selectors. Continue refining medium-confidence field names. |
| `$C200-$C2FF` | `SPRITE_OBJECTS`; 16 logical sprite object slots, `$10` bytes each. | `UpdateSprites` scans this page in `$10`-byte steps and expands active slots into shadow OAM; `UpdateSpriteObject` stages gameplay slots 1-4 through `$C68C-$C695`. |
| `$C300-$C3FF` | Sprite/field-adjacent work area, not yet fully mapped. | Some references may still be from real field/UI state or from older data artifacts; needs separate trace. |
| `$C400-$C49F` | `SHADOW_OAM`; 40 hardware OAM entries. | `ClearOAM` clears `$A0` bytes; HRAM OAM DMA copies page `$C4` to hardware OAM; `UpdateSprites` appends entries here. |
| `$C4A0-$C5FF` | Used by result/title/2P display routines as data destinations. | UI/OAM/meta-sprite buffers and display work area. |
| `$C6C3-$C6CE` | Field drawing routines use these as animation indexes, redraw flags, and timers. | Field redraw animation state. Consider naming once all producers are traced. |
| `$C6EB-$C6EC` | Used by 2P initialization as sources for `ACTIVE_LEVEL`/`ACTIVE_SPEED`. | Link/2P selected level and speed staging bytes. |
| `$C6D2-$C6D5` | Cleared/initialized with sprite animation state; used by playfield/egg logic. | Per-player or per-side animation/playfield state. |
| `$C6FA-$C6FE` | 2P/link code uses these with `LINK_SEND`/`LINK_RECV`. | Link protocol staging bytes / last exchanged settings. |
| `$C7A9-$C7CF` | Title/result/high-score-like code writes here. | UI/result state tables; needs trace. |

## Code/Data Misclassification Candidates

The reference scan intentionally reports address-like operands even when they occur in suspicious code. These are high-value cleanup targets because they can hide real tables.

| Area | Evidence | Action |
|------|----------|--------|
| `Yoshi/bank_001.asm` `01:$40A0-$42F4` | `UpdateSprites` indexes `$40A0` as a pointer table; the range before `UpdateAnimFrame` was previously decoded as bogus instructions. | Converted to `SpriteUpdatePointerTable`/`SpriteUpdateData_*` in source. |
| `Yoshi/bank_001.asm` `01:$442C-$445B` | `LoadGameBGTiles` indexes `$442C` as six 16-byte records before real code at `$445C`. | Converted to `FieldColumnTilePatternTable`; `$445C` is now the real `StartNextRound` entry. |
| `Yoshi/bank_001.asm` `01:$55E2-$5668` | `SoundEngine` and `SoundLookupIndex` jump to `$55E2`; the bytes form a coherent sound setup routine. | Converted to `StartSoundSequence` code. |
| `Yoshi/bank_001.asm` `01:$5669-$5699` | Sound routines directly index `$566A`, `$5672`, `$567A`, and `$5682`; `$569A` is a sequence entry target, not pitch-table data. | Split into small sound support tables. |
| `Yoshi/bank_001.asm` `01:$569A-$5FE2` | Already represented as `db`, but was mostly one large unlabeled sequence block. | Added first-pass internal pointer-target labels. |
| `Yoshi/bank_001.asm` `01:$5FE3-$7C01` | Previously contained many instruction-looking bytes and fake labels. | Converted to `MusicSequenceData_*` blocks while preserving the real `$7C02` helper. |
| `Yoshi/bank_000.asm` `00:$22CC-$234B` | Field drawing routines index `$22CC` and `$230F` with `GetArrayElement`; `$234C` is called from Bank 0 and Bank 1 as code. | Converted to `FieldSideDeltaTable` and `FieldRowDeltaTable`; restored `UpdateFieldTimers` at `$234C`. |
| `Yoshi/bank_000.asm` `00:$3839-$3FFF` | `ShowWinScreen` / result setup copies `$3839` and `$3D39` to VRAM via `VRAMCopySetup`; the area is dense 2bpp tile data and produced fake jumps when decoded as code. | Converted to `TitleResultTileData0`, `TitleResultTileData1`, and `Bank0TailGraphicsData`. |

## Immediate Next Steps

1. Refine medium-confidence `SOUND_CH_*` slide/tempo/envelope names by decoding more sequence examples.
2. Trace `GAME_STATE` writes and assign concrete state names.
3. Trace `$C6EB-$C6EC` and adjacent 2P setting staging bytes.
4. Decode the visual meaning of each Bank 2/3 graphics load range.
5. Confirm the `$FFB3` secondary VRAM count path.
