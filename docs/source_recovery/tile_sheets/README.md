# Rendered Game Boy Tile Sheets

Source ROM: `Yoshi/yoshi.gb`

Each image decodes 16-byte Game Boy 2bpp tiles in address order. The grid shows tile boundaries; generated images are evidence aids, not source assets.

| File | Bank | Address | Size | Tiles | Notes |
|------|------|---------|------|-------|-------|
| `bank2_game_tileset.png` | `$02` | `$4000` | `$0800` | 128 | GameTileSet -> $8000/$8000-area loads |
| `bank2_common_tileset.png` | `$02` | `$4800` | `$1000` | 256 | CommonTileSet -> $8800 loads |
| `bank2_extra_tiles.png` | `$02` | `$5800` | `$0800` | 128 | ExtraTiles -> pre-play $8800 overlay |
| `bank2_title_tileset.png` | `$02` | `$6000` | `$1000` | 256 | TitleTileSet -> title $8800 load |
| `bank2_two_player_tiles1.png` | `$02` | `$6F70` | `$0260` | 38 | TwoPlayerTiles1 -> $81C0, 2P role-dependent |
| `bank2_two_player_tiles2.png` | `$02` | `$71D0` | `$0200` | 32 | TwoPlayerTiles2 -> $9500, 2P |
| `bank3_full_tile_graphics_data2.png` | `$03` | `$4000` | `$4000` | 1024 | Full Bank 3 graphics block |
| `bank3_matching_4000.png` | `$03` | `$4000` | `$0800` | 128 | ProcessMatching -> $9000 |
| `bank3_matching_4800.png` | `$03` | `$4800` | `$0800` | 128 | ProcessMatching -> $8800 |
| `bank3_matching_4e40.png` | `$03` | `$4E40` | `$0800` | 128 | ProcessMatching -> $8000 |
| `bank3_result_5400.png` | `$03` | `$5400` | `$0800` | 128 | Result/round setup -> $9000 |
| `bank3_result_5c00.png` | `$03` | `$5C00` | `$0800` | 128 | Result/round setup -> $8800 |
| `bank3_high_score_5dd0.png` | `$03` | `$5DD0` | `$0800` | 128 | High-score/result path -> $9000 |
| `bank3_high_score_65d0.png` | `$03` | `$65D0` | `$0800` | 128 | High-score/result path -> $8800 |
| `bank3_high_score_overlay_6ab0.png` | `$03` | `$6AB0` | `$0390` | 57 | Conditional overlay -> $9470 |
| `bank3_high_score_overlay_6e40.png` | `$03` | `$6E40` | `$0740` | 116 | Conditional overlay -> $8800 |
| `rom0_title_result_tiles0.png` | `$00` | `$3839` | `$0500` | 80 | TitleResultTileData0 -> queued $8820 |
| `rom0_title_result_tiles1.png` | `$00` | `$3D39` | `$0110` | 17 | TitleResultTileData1 -> queued $9140 |
