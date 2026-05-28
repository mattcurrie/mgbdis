# Link State

This note documents the recovered 2-player/link staging bytes around
`$C6EB-$C700`.

## 2P Option Selection

| Address | Name | Evidence |
|---------|------|----------|
| `$C6EB` | `LINK_2P_SELECTED_LEVEL` | The 2P option loop edits this byte through `MENU_SELECT`, `UpdateGameField` sends it in the high nibble, and the 2P game setup copies it into `ACTIVE_LEVEL`. |
| `$C6EC` | `LINK_2P_SELECTED_SPEED` | The 2P option loop edits this byte through `MENU_SELECT`, `UpdateGameField` sends it in the low nibble, and the 2P game setup copies it into `ACTIVE_SPEED`. |
| `$C6FF` | `LINK_RECV_LEVEL` | `UpdateGameField` receives a packed peer option byte, stores the high nibble here, and the preview/result path draws it as the peer selection. |
| `$C700` | `LINK_RECV_SPEED` | `UpdateGameField` receives a packed peer option byte, stores the low nibble here, and result text chooses the peer speed label from it. |

`UpdateGameField` packs `LINK_2P_SELECTED_LEVEL << 4 | LINK_2P_SELECTED_SPEED`
into `LINK_SEND`. The peer unpacks the received byte into `LINK_RECV_LEVEL`
and `LINK_RECV_SPEED`.

## Send Queue

| Address | Name | Evidence |
|---------|------|----------|
| `$C6FC` | `LINK_SEND_QUEUE_0` | `TimerTickCore` alternates between `$C6FC` and `$C6FD`, sends the selected byte through `LINK_SEND`, then clears that queue byte. |
| `$C6FD` | `LINK_SEND_QUEUE_1` | The second queue byte used by `TimerTickCore`; several producers mirror urgent values into both queue slots. |
| `$C6FE` | `LINK_SEND_QUEUE_INDEX` | Alternates between `0` and `1` to select the next queued send byte. |

`LINK_FIELD_EVENT_PAYLOAD` (`$C6E6`) is a staging byte for bit-6 field events.
The falling-piece path builds the payload by ORing `$40`, then later copies it
to `LINK_SEND_QUEUE_0`.

`LINK_PENDING_FIELD_RISE` (`$C6FA`) accumulates incoming bit-6 values. The
selector/gameplay path consumes it in chunks and adjusts `SCREEN_STATE` while
playing the associated sound effect.

`LINK_STAGING_BYTE` (`$C6FB`) is cleared with the link state, but no direct read
has been confirmed.
