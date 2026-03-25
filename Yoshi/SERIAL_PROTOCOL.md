# Yoshi's Egg - 2P Serial Communication Protocol

## Overview

Game Boy Link Cable を使用した2人対戦通信プロトコル。
マスター/スレーブ方式で、マスターがクロックを制御する。

## Roles

`LINK_ROLE` ($C6BB) で3つの状態を管理:

| Value | Role | Description |
|-------|------|-------------|
| $00 | None | 未接続 (1Pモード) |
| $01 | Master | クロック制御側 (内部クロック) |
| $02 | Slave | クロック受信側 (外部クロック) |

## Hardware Registers

| Register | Address | Usage |
|----------|---------|-------|
| rSB | $FF01 | シリアル転送データレジスタ |
| rSC | $FF02 | シリアル転送制御 ($80=転送開始, $81=内部クロック+転送) |
| rDIV | $FF04 | タイマー (同期待ちに使用) |

## Key RAM Addresses

| Address | Name | Description |
|---------|------|-------------|
| $C6B9 | LINK_RECV | 受信バイト |
| $C6BA | LINK_SEND | 送信バイト |
| $C6BB | LINK_ROLE | ロール |
| $FFC8 | SERIAL_DONE | 転送完了フラグ (1=完了) |
| $FFE0 | SERIAL_TEMP | 一時レジスタ |

## SerialHandler ($2092) - Serial Interrupt

シリアル転送完了割り込み ($0058 → SerialHandler) で呼ばれる。

### Flow

```text
SerialHandler:
  if LINK_ROLE == 0 (None):
    → 受信バイトを読み取り
    → 受信値が $02 なら SB をクリア
    → それ以外: DIVタイマー待ち → 転送開始 ($80)
  else (Master/Slave):
    → rSB → LINK_RECV に保存
    → LINK_SEND → rSB にセット
    → Master: クロック開始不要 (内部クロックは自動)
    → Slave: $80 を rSC に書き込み (外部クロック待ち)
  → SERIAL_DONE = 1
  → reti
```

### Master vs Slave

- **Master** (LINK_ROLE=$01): 内部クロックを使用。`rSC = $81` で転送を開始する側。
  ゲームループ側 (`SetupLinkCable`) で転送を開始。
- **Slave** (LINK_ROLE=$02): 外部クロック待ち。`rSC = $80` をセットして Master からの転送を待つ。

## Handshake - SetupLinkCable ($21EB)

接続確立時のハンドシェイク:

1. 両方の Game Boy が `rSB = $02` をセット
2. Master: `rSC = $81` (内部クロック+転送開始)
3. Slave: `rSC = $80` (外部クロック待ち)
4. 転送完了 → 互いに `$02` を受信 → 接続確立

## Bank 1: Link Communication ($4C48-$4D63)

### ProcessLinkData ($4C48)

VBlank ハンドラから呼ばれる通信データ処理:

```text
ProcessLinkData:
  if sound_busy ($C002 != 0): return
  if $C6E4 == 0: call SendLinkByte($C6DA)
  if $C6E5 != 0: return
  → SendLinkByte($C6DF)
```

### SendLinkByte ($4C61)

多段カウンタによるデータ送信タイミング制御:

```text
SendLinkByte(HL):
  [HL+0]++        ; frame counter (0-59)
  if < $3C: return
  [HL+0] = 0
  [HL-1]++        ; sub-second counter (0-9)
  if < $0A: return
  [HL-1] = 0
  [HL-2]++        ; second counter (0-5)
  if < $06: return
  [HL-2] = 0
  [HL-3]++        ; minute counter (0-9)
  if < $0A: return
  → overflow: reset all to max
```

### UpdateLinkState ($4C91)

8チャンネル分のサウンド/通信状態を更新:

```text
for c = 0 to 7:
  if channel[c] active:
    if c < 4 (sound channels):
      handle sound priority
    else:
      call SyncLinkPlayers
```

### SyncLinkPlayers ($4CC6)

チャンネルデータの同期処理。サウンドシーケンスステップと連携。

## Data Flow

```text
Game Logic (Bank 0)
  ↓ LINK_SEND に送信データセット
  ↓ SerialHandler (割り込み)
  ↓ rSB ↔ rSB (Link Cable 物理転送)
  ↓ LINK_RECV に受信データ保存
  ↓ SERIAL_DONE = 1
  ↓
VBlank Handler (Bank 1)
  → ProcessLinkData
  → UpdateLinkState
  → SyncLinkPlayers
  ↓
Game Logic に結果反映
```

## Communication Timing

- 通信はフレーム単位 (VBlank ごと) で処理
- SendLinkByte の多段カウンタはゲーム内タイマー表示用
- 実際のデータ転送は SerialHandler の割り込みで即座に実行
