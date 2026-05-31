# Link State

This note documents the recovered 2-player/link staging bytes around
`$C6EB-$C700`.

## 2P Option Selection

| Address | Name | Evidence |
|---------|------|----------|
| `$C6EB` | `LINK_2P_SELECTED_LEVEL` | The 2P option loop edits this byte when `LINK_SETTINGS_CURSOR` selects row 0, `Exchange2PPreplaySettings` sends it in the high nibble, and the 2P game setup copies it into `ACTIVE_LEVEL`. |
| `$C6EC` | `LINK_2P_SELECTED_SPEED` | The 2P option loop edits this byte when `LINK_SETTINGS_CURSOR` selects row 1, `Exchange2PPreplaySettings` sends it in the low nibble, and the 2P game setup copies it into `ACTIVE_SPEED`. |
| `$C6E7` | `LINK_SEND_DROP_INPUT_LOCK` | `Send2PData` stores `LINK_SEND_DROP_INPUT_LOCK_ACTIVE` around its embedded `HandlePlayfieldInput` call; `HandlePlayfieldInput` still handles movement but suppresses starting a new drop while the link-send wait loop is running. |
| `$C6FF` | `LINK_RECV_LEVEL` | `Exchange2PPreplaySettings` receives a packed peer option byte, stores the high nibble here, and the preview/result path draws it as the peer selection. |
| `$C700` | `LINK_RECV_SPEED` | `Exchange2PPreplaySettings` receives a packed peer option byte, stores the low nibble here, and result text chooses the peer speed label from it. |
| `$C708` | `LINK_PEER_RESULT_CODE` | `Exchange2PResultCode` waits for a `LINK_RESULT_PACKET_FLAG` bit-7 result packet from the peer, clears `LINK_RESULT_PACKET_BIT`, and stores the peer code here for `ResolveResultRankPosition` to compare against the local result code. |
| `$C6F0` | `LINK_SETTINGS_CURSOR` | The 2P pre-play loop moves this cursor between level (`0`) and speed (`1`) and uses it to index `LINK_2P_SELECTED_LEVEL` / `LINK_2P_SELECTED_SPEED`. |
| `$C701` | `LINK_RESULT_NONZERO_MARKS` | `UpdateLinkResultMarksAndScreen` increments this when the result code is nonzero; the result panel draws that many 2x2 marks from `LINK_RESULT_NONZERO_MARK_BASE` (`$C4F3`) rightward. |
| `$C702` | `LINK_RESULT_ZERO_MARKS` | `UpdateLinkResultMarksAndScreen` increments this when the result code is zero; the result panel draws that many 2x2 marks from `LINK_RESULT_ZERO_MARK_BASE` (`$C4FF`) leftward. |

`Exchange2PPreplaySettings` packs `LINK_2P_SELECTED_LEVEL << 4 | LINK_2P_SELECTED_SPEED`
into `LINK_SEND`. The peer unpacks the high and low nibbles with
`LINK_SETTINGS_NIBBLE_MASK` into `LINK_RECV_LEVEL` and `LINK_RECV_SPEED`. The
`LINK_ROLE_MASTER` path starts the transfer at
`Start2PPreplaySettingsExchange`; both roles wait in
`Wait2PPreplaySettingsSerialDone` until `SERIAL_DONE` is set. A received
`LINK_CONFIRM_BYTE` is treated as the start handshake and returns before
updating the peer option bytes.

`Handle2PPreplayNonStartInput` handles the non-Start inputs in the 2P pre-play
loop. Up/down call `Move2PPreplayCursorUp` / `Move2PPreplayCursorDown` and clamp
`LINK_SETTINGS_CURSOR` to the level/speed rows; left/right call
`Increment2PPreplaySelectedSetting` / `Decrement2PPreplaySelectedSetting` and
edit the selected byte from `LINK_2P_SELECTED_LEVEL`. The direction tests use
the hardware `PADB_UP`, `PADB_DOWN`, `PADB_RIGHT`, and `PADB_LEFT` bit
constants.
`LinkSettingsOptionCountTable` emits `LINK_SETTINGS_OPTION_COUNT_ENTRY` records
for the exclusive upper bounds of those two rows:
`LINK_SETTINGS_LEVEL_OPTION_COUNT` level choices and
`LINK_SETTINGS_SPEED_OPTION_COUNT` speed choices.

The 2P start path uses `LINK_CONFIRM_BYTE` as the pre-play start handshake byte.
`Check2PPreplayReceivedStartHandshake` waits for the peer byte on the non-master
path, while `Enter2PPreplayPlaySetup` clears the link send/receive bytes before
calling `InitGameState` and entering `GAME_STATE_PLAY_SETUP`.

`SerialHandler` has a common `FinishSerialInterrupt` tail that marks
`SERIAL_DONE` with `SERIAL_DONE_ACTIVE`. When `LINK_ROLE` is zero,
`HandleUnassignedSerialRole` reads `rSB` into `LINK_RECV`; if the byte is
`TITLE_LINK_READY_BYTE`, `ClearUnassignedSerialByte` clears `rSB` and exits
without starting another transfer, otherwise the handler waits on `rDIV` before
writing `SERIAL_TRANSFER_EXTERNAL_CLOCK` to `rSC`. The unassigned-role restart
path writes the observed `SERIAL_DIV_RESET_WRITE_VALUE` to `rDIV` before the
bit-7 wait.

## 2P Preplay Screen Layout

`Draw2PPreplayBackground` fills the full 20x18 setup screen with
`PREPLAY_2P_BACKGROUND_TILE`, then clears the upper and lower six-row panels
with `PREPLAY_2P_PANEL_CLEAR_TILE`. The panel names stay top/bottom because
`Draw2PPreplayRolePanels` swaps the displayed role art according to
`LINK_ROLE`. The level and speed labels reuse the shared
`PREPLAY_LEVEL_LABEL_*` and `PREPLAY_SPEED_LABEL_*` tile-row constants used by
the 1P setup screen. The role header, top/bottom role panels, local/peer level
preview coordinates, and local/peer speed text coordinates now use
`PREPLAY_2P_*` layout constants. The role panel tile bases are named by
master/slave role because `Draw2PPreplayRolePanels` swaps them when the local
link role is slave.

## 2P Result Screen Layout

`UpdateLinkResultMarksAndScreen` rebuilds the 2P result tilemap in
`BG_MAP_SHADOW` before the normal VBlank slice copier pushes it to VRAM. The
left/right header fields and 2x2 badge boxes swap tile bases according to
`LINK_ROLE`, so the names describe screen positions rather than player
semantics:

The routine first updates the local result counters: `IncrementLinkZeroResultMarks`
handles `ROUND_RESULT_CODE_ZERO`, the nonzero path increments
`LINK_RESULT_NONZERO_MARKS`, and `SetTerminalLinkResultFlagIfMarkLimitReached` raises
`STATE_TRANSITION` once either side reaches `LINK_RESULT_MARK_LIMIT` marks. The
path first clears the terminal flag with `LINK_RESULT_TERMINAL_FLAG_CLEAR`, so
only a just-reached mark limit enables the terminal overlay and terminal-mode
dispatch.
`BuildLinkResultScreen` then reloads the link-result tiles, optionally
copies the terminal overlay tile ranges using the `BANK3_LINK_RESULT_*` copy
size constants, clears `BG_MAP_SHADOW`, and rebuilds the screen layout. The
mark fill loops are now named
`DrawFilledNonzeroResultMarksLoop` and `DrawFilledZeroResultMarksLoop`, matching
the two opposing 2x2 mark runs.

| Address | Name | Evidence |
|---------|------|----------|
| `$C4B7/$C4C3` | `LINK_RESULT_LEFT_BADGE_TOP_LEFT` / `LINK_RESULT_RIGHT_BADGE_TOP_LEFT` | `UpdateLinkResultMarksAndScreen` fills two 2x2 boxes with `LINK_RESULT_BADGE_MASTER_TILE` / `LINK_RESULT_BADGE_NONMASTER_TILE`, swapped by `LINK_ROLE`. |
| `$C4CD/$C4D3` | `LINK_RESULT_LEFT_HEADER_TOP_LEFT` / `LINK_RESULT_RIGHT_HEADER_TOP_LEFT` | The same setup fills two one-row, four-tile header blocks with `LINK_RESULT_HEADER_MASTER_TILE` / `LINK_RESULT_HEADER_NONMASTER_TILE`, also swapped by `LINK_ROLE`. |
| `$C572/$C574` | `LINK_RESULT_OUTCOME_LEFT_TOP_LEFT` / `LINK_RESULT_OUTCOME_RIGHT_TOP_LEFT` | The terminal 2P result branch fills one of two 4x3 outcome blocks with `LINK_RESULT_OUTCOME_TILE_A` / `LINK_RESULT_OUTCOME_TILE_B`, choosing left or right from `LINK_ROLE` and `ANIM_FRAME`. |
| `$C543` | `LINK_RESULT_WAIT_PANEL_TOP_LEFT` | `WaitLinkStartConfirm` repeatedly fills this 6x6 panel with the tile base selected before entering the link confirmation wait. |
| `$C571` | `LINK_RESULT_CONFIRM_DETAIL_TOP_LEFT` | `DrawLinkResultConfirmPanelsAndWait` fills this 4x3 detail block for the non-master role, alternating tile bases through `ANIM_FRAME`. |
| `$C5D0` | `LINK_RESULT_STATUS_TOP_LEFT` | `DrawLinkResultRoleStatusStrip` and the terminal result branch fill the two-row status strip here with `LINK_RESULT_STATUS_TEXT_TILE_A` / `LINK_RESULT_STATUS_TEXT_TILE_B`, or clear it with `LINK_RESULT_STATUS_CLEAR_TILE`. |
| `$C5D7` | `LINK_RESULT_BOTTOM_TEXT_TOP_LEFT` | The terminal result branch fills a two-row, five-tile text block here with the same status-text tile-base pair after choosing the outcome block. |

When `STATE_TRANSITION` is set, `DispatchLinkResultScreenMode` chooses the
terminal branch instead of the normal confirm sound path. The role/result cases
are split as `DrawMasterZeroTerminalLinkResult`,
`DrawNonMasterTerminalLinkResult`, and `DrawNonMasterZeroTerminalLinkResult`;
the remaining master/nonzero case falls through to the link confirm wait setup.
The terminal sound IDs are now named by the same branch evidence:
`SND_LINK_RESULT_NONZERO` for nonzero `ANIM_FRAME` and
`SND_LINK_RESULT_ZERO` for zero `ANIM_FRAME`.
`LoadZeroTerminalLinkResultSound` names the zero-result sound load, and
`PlayTerminalLinkResultSoundAndClearResultAreas` names the shared terminal
tail: it plays the selected sound, clears `SERIAL_DONE` / `LINK_SEND`, and
clears the status strip plus score-value area before role/result drawing.

`WaitLinkStartConfirm` animates `LINK_RESULT_WAIT_PANEL_TOP_LEFT` by alternating
between the base tile in `UI_SCRATCH` and the alternate tile in `ANIM_SUBFRAME`.
The base tile is used until `LINK_RESULT_WAIT_PANEL_ALT_START_FRAME` (`$1E`);
the frame counter wraps at `LINK_RESULT_WAIT_PANEL_ANIM_PERIOD` (`$3C`).
`CheckLinkConfirmRole` branches between the `LINK_ROLE_MASTER` `PADF_START`
serial send and the non-master `LINK_RECV == LINK_CONFIRM_BYTE` wait. Both the
master no-Start loop and the non-master no-confirm loop return through
`ContinueLinkConfirmWait`, preserving the current frame counter after the
initial `WaitLinkStartConfirm` reset. Both confirmed paths return through
`ReturnLinkConfirmWithCarry`. The wait loop starts
`SND_LINK_RESULT_CONFIRM_WAIT` only when neither it nor the nonzero terminal
result sound is already active.

The normal confirm path starts at `DrawLinkResultConfirmPanelsAndWait`.
`DrawLinkResultConfirmMainPanel` fills the central result panel,
`DrawNonMasterConfirmDetailPanel` draws the non-master detail block when
needed, and `HandleLinkResultClearConfirmOutcome` /
`HandleLinkResultGameOverConfirmOutcome` choose whether
`FillLinkResultWideScoreArea` or `FillLinkResultNarrowScoreArea` is paired with
`DrawLinkResultRoleStatusStrip` or the animated status strip.
`WaitLinkResultConfirmAndReloadTiles` then waits for the same master Start or
peer `LINK_CONFIRM_BYTE` confirm before `ReloadGameTilesAfterLinkResultConfirm`
reloads the game tiles and returns without carry.
`WaitTerminalLinkResultMenuConfirm` starts
`SND_LINK_RESULT_MENU_WAIT` unless that sound or the zero-result sound is
already active.

The terminal/result confirm path now uses named tile constants for the main
panel, non-master detail panel, score clear/fill areas, and the two wait-panel
tile pairs. `FillLinkResultWideScoreArea` fills a 2x7 block from tile `$47`,
while `FillLinkResultNarrowScoreArea` fills a 2x6 block from tile `$2D`; the
names stay tied to the observed tilemap dimensions rather than claiming final
text semantics for the underlying tile art.

## 2P Playfield Role Headers

`DrawTwoPlayerPlayfieldRoleHeaders` draws two four-tile header rows on the 2P
playfield. The top row uses `TWO_PLAYER_ROLE_HEADER_TOP_COORD` and the bottom
row uses `TWO_PLAYER_ROLE_HEADER_BOTTOM_COORD`. Tile rows
`TWO_PLAYER_ROLE_HEADER_TILE_ROW_0` and `TWO_PLAYER_ROLE_HEADER_TILE_ROW_1` are
swapped when `LINK_ROLE` is `LINK_ROLE_SLAVE`, so the helper name records the
link-role dependency without assigning a permanent player-side meaning to either
screen position.

## Send Queue

| Address | Name | Evidence |
|---------|------|----------|
| `$C6FC` | `LINK_SEND_QUEUE_0` | `TimerTickCore` alternates between `$C6FC` and `$C6FD`, sends the selected byte through `LINK_SEND`, then clears that queue byte. |
| `$C6FD` | `LINK_SEND_QUEUE_1` | The second queue byte used by `TimerTickCore`; several producers mirror urgent values into both queue slots. |
| `$C6FE` | `LINK_SEND_QUEUE_INDEX` | Alternates modulo `LINK_SEND_QUEUE_SLOT_COUNT` between `0` and `1` to select the next queued send byte. |

`Send2PData` performs repeated gameplay/link wait frames. While it is waiting,
it sets `LINK_SEND_DROP_INPUT_LOCK_ACTIVE` before calling `HandlePlayfieldInput`, then
clears the lock before `UpdateFieldAnimationSlots` / `UpdateFieldTimers`. If
`ROUND_RESULT_PENDING` is already set or the game state is no longer playing,
`AbortSend2PDataFrames` unwinds the send-frame wait early.

`LINK_FIELD_EVENT_PAYLOAD` (`$C6E6`) is a staging byte for bit-6 field events.
The falling-piece path builds the payload by ORing `LINK_FIELD_EVENT_FLAG`
(`$40`), then later copies it to `LINK_SEND_QUEUE_0`.

`LINK_PENDING_FIELD_RISE` (`$C6FA`) accumulates incoming bit-6 values. The
`ProcessLinkFieldRisePacket` clears `LINK_FIELD_EVENT_BIT` and adds the
remaining payload to it, and the selector/gameplay path consumes it in chunks
while adjusting `SCREEN_STATE` and playing the associated sound effect.
`SelectTwoPlayerPieceDisplayCount` enters that path, `ConsumePendingFieldRiseForDisplayCount` compares
the pending count with the remaining capacity up to
`LINK_FIELD_RISE_SCREEN_STATE_LIMIT`,
`ApplyPartialPendingFieldRise` consumes a smaller pending count, and
clears the pending byte to `LINK_PENDING_FIELD_RISE_NONE`. Then
`PlayPendingFieldRiseSound` plays `SND_LINK_FIELD_RISE` after choosing the
returned state.

`DispatchReceivedLinkPacket` tests received packets in pause, result,
field-count, then field-rise order. The field-count and field-rise tests are
named `DispatchReceivedLinkFieldCountPacket` and
`DispatchReceivedLinkFieldRisePacket` to keep the packet dispatcher separate
from the actual packet handlers.

`LINK_UNUSED_STAGING_BYTE` (`$C6FB`) is cleared with the link state, but no
direct read has been confirmed.

`ClearLinkRoundState` clears the round-local link staging bytes:
`LINK_SEND_QUEUE_INDEX`, `LINK_PENDING_FIELD_RISE`, `LINK_SEND`, `LINK_RECV`,
`LINK_UNUSED_STAGING_BYTE`, `LINK_SEND_QUEUE_0`, `LINK_SEND_QUEUE_1`, and
`LINK_FIELD_EVENT_PAYLOAD`.

## Field Occupancy Count Packet

The 2P gameplay path counts non-empty tiles in a fixed 7x4 sample of
`BG_MAP_SHADOW` and mirrors that count through the link send queue.
`ScanLinkFieldOccupancyRow` and `ScanLinkFieldOccupancyColumn` name the nested
row/column loops in that sampler, while `DrawTwoDigitLinkFieldCount` uses
`CountLinkFieldTensDigitLoop` before storing the tens/ones tile digits.

| Address / Value | Name | Evidence |
|-----------------|------|----------|
| `$C4C8` | `FIELD_OCCUPANCY_SCAN_TOP_LEFT` | `CountFieldOccupancyIntoUiScratch` scans from row 2, column 0 through `FieldOccupancyScanRowLoop` / `FieldOccupancyScanColumnLoop`; `QueueLinkFieldOccupancyCount` scans the same four columns across seven two-row steps. |
| `$4A` | `FIELD_OCCUPANCY_EMPTY_TILE` | Scan entries equal to this tile are ignored; any other sampled tile increments the count. |
| `$0A` | `FIELD_OCCUPANCY_COUNT_DECIMAL_BASE` | `DrawTwoDigitLinkFieldCount` repeatedly subtracts this value while building the tens digit before adding `FIELD_OCCUPANCY_COUNT_DIGIT_BASE`. |
| `$20` / bit 5 | `LINK_FIELD_COUNT_PACKET_FLAG` / `LINK_FIELD_COUNT_PACKET_BIT` | `QueueLinkFieldOccupancyCount` ORs the local count with this flag before placing it in `LINK_SEND_QUEUE_1`; `TimerTickCore` dispatches matching packets to `ProcessLinkFieldCountPacket`, which clears the bit before drawing the peer count. |
| `$C565-$C566` | `LINK_LOCAL_FIELD_COUNT_TENS/ONES` | The local count is drawn here as two tile digits with base `FIELD_OCCUPANCY_COUNT_DIGIT_BASE` (`$40`). |
| `$C5DD-$C5DE` | `LINK_PEER_FIELD_COUNT_TENS/ONES` | Incoming bit-5 packets are decoded and drawn here; the bit-7 result path clears both digits to `$40` when queueing a zero result. |

## Result Code Packet

`ProcessRoundResultAndEnterRoundEnd` calls `Exchange2PResultCode` with the local result code
in `A`. In 2P mode the helper sends `local | LINK_RESULT_PACKET_FLAG` until it
sees a peer `LINK_RESULT_PACKET_BIT` packet, then stores the cleared peer value
in `LINK_PEER_RESULT_CODE`. `ProcessLinkResultPacket` handles asynchronously
received bit-7 packets during normal link ticks, reads
`LINK_RESULT_CODE_BIT`, and queues either `ROUND_RESULT_CODE_ZERO` or
`ROUND_RESULT_CODE_NONZERO` through `QueueLinkResultPacketOutcome` /
`QueueRoundResult`.
