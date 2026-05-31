# Rendered Game Boy Tile Sheets

Source ROM: `Yoshi/yoshi.gb`

Each image decodes 16-byte Game Boy 2bpp tiles in address order. The grid shows tile boundaries; generated images are evidence aids, not source assets.

| File | Bank | Address | Size | Tiles | Notes |
|------|------|---------|------|-------|-------|
| `bank2_game_tileset.png` | `$02` | `$4000` | `$0800` | 128 | GameTileSet -> $8000/$8000-area loads |
| `bank2_common_tileset.png` | `$02` | `$4800` | `$1000` | 256 | CommonTileSet -> $8800 loads |
| `bank2_preplay_menu_overlay_tiles.png` | `$02` | `$5800` | `$0800` | 128 | PreplayMenuOverlayTiles -> pre-play $8800 overlay |
| `bank2_title_tileset.png` | `$02` | `$6000` | `$1000` | 256 | TitleTileSet -> title $8800 load |
| `bank2_two_player_nonmaster_tiles.png` | `$02` | `$6F70` | `$0260` | 38 | TwoPlayerNonMasterTiles -> $81C0, skipped for master |
| `bank2_two_player_shared_tiles.png` | `$02` | `$71D0` | `$0200` | 32 | TwoPlayerSharedTiles -> $9500, all 2P |
| `bank2_unused_tail_tile_data.png` | `$02` | `$73D0` | `$0C30` | 195 | Bank2UnusedTailTileData, no confirmed load |
| `bank3_full_graphics_data.png` | `$03` | `$4000` | `$4000` | 1024 | Bank3GraphicsData full graphics block |
| `bank3_matching_tiles_to9000.png` | `$03` | `$4000` | `$0800` | 128 | Bank3MatchingTilesTo9000 -> $9000 |
| `bank3_matching_tiles_to8800.png` | `$03` | `$4800` | `$0800` | 128 | Bank3MatchingTilesTo8800 -> $8800 |
| `bank3_matching_tiles_to8000.png` | `$03` | `$4E40` | `$0800` | 128 | Bank3MatchingTilesTo8000 -> $8000 |
| `bank3_result_record_tiles_to9000.png` | `$03` | `$5400` | `$0800` | 128 | Bank3ResultRecordTilesTo9000 -> $9000 |
| `bank3_result_record_tiles_to8800.png` | `$03` | `$5C00` | `$0800` | 128 | Bank3ResultRecordTilesTo8800 -> $8800 |
| `bank3_link_result_5dd0.png` | `$03` | `$5DD0` | `$0800` | 128 | Link-result names/text/number fragments -> $9000 |
| `bank3_link_result_65d0.png` | `$03` | `$65D0` | `$0800` | 128 | Link-result character and border fragments -> $8800 |
| `bank3_link_result_overlay_6ab0.png` | `$03` | `$6AB0` | `$0390` | 57 | Conditional terminal link-result character overlay -> $9470 |
| `bank3_link_result_overlay_6e40.png` | `$03` | `$6E40` | `$0740` | 116 | Conditional terminal link-result character overlay -> $8800 |
| `rom0_round_complete_summary_graphics.png` | `$00` | `$3839` | `$0500` | 80 | RoundCompleteSummaryGraphicTileData -> queued $8820 |
| `rom0_round_complete_summary_text.png` | `$00` | `$3D39` | `$0110` | 17 | RoundCompleteSummaryTextTileData glyph records -> queued $9140 |
