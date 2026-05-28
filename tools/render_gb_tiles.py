#!/usr/bin/env python3
"""Render Game Boy 2bpp tile ranges from a ROM to PNG sheets."""

from __future__ import annotations

import argparse
import math
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path


PALETTES = {
    "dmg": (
        (232, 248, 208),
        (160, 192, 96),
        (72, 104, 56),
        (16, 24, 16),
    ),
    "gray": (
        (255, 255, 255),
        (170, 170, 170),
        (85, 85, 85),
        (0, 0, 0),
    ),
}


@dataclass(frozen=True)
class TileRange:
    name: str
    bank: int
    address: int
    size: int
    note: str


YOSHI_GRAPHICS_RANGES = (
    TileRange("bank2_game_tileset", 2, 0x4000, 0x0800, "GameTileSet -> $8000/$8000-area loads"),
    TileRange("bank2_common_tileset", 2, 0x4800, 0x1000, "CommonTileSet -> $8800 loads"),
    TileRange("bank2_extra_tiles", 2, 0x5800, 0x0800, "ExtraTiles -> pre-play $8800 overlay"),
    TileRange("bank2_title_tileset", 2, 0x6000, 0x1000, "TitleTileSet -> title $8800 load"),
    TileRange("bank2_two_player_tiles1", 2, 0x6F70, 0x0260, "TwoPlayerTiles1 -> $81C0, 2P role-dependent"),
    TileRange("bank2_two_player_tiles2", 2, 0x71D0, 0x0200, "TwoPlayerTiles2 -> $9500, 2P"),
    TileRange("bank3_full_tile_graphics_data2", 3, 0x4000, 0x4000, "Full Bank 3 graphics block"),
    TileRange("bank3_matching_4000", 3, 0x4000, 0x0800, "ProcessMatching -> $9000"),
    TileRange("bank3_matching_4800", 3, 0x4800, 0x0800, "ProcessMatching -> $8800"),
    TileRange("bank3_matching_4e40", 3, 0x4E40, 0x0800, "ProcessMatching -> $8000"),
    TileRange("bank3_result_5400", 3, 0x5400, 0x0800, "Result/round setup -> $9000"),
    TileRange("bank3_result_5c00", 3, 0x5C00, 0x0800, "Result/round setup -> $8800"),
    TileRange("bank3_high_score_5dd0", 3, 0x5DD0, 0x0800, "High-score/result path -> $9000"),
    TileRange("bank3_high_score_65d0", 3, 0x65D0, 0x0800, "High-score/result path -> $8800"),
    TileRange("bank3_high_score_overlay_6ab0", 3, 0x6AB0, 0x0390, "Conditional overlay -> $9470"),
    TileRange("bank3_high_score_overlay_6e40", 3, 0x6E40, 0x0740, "Conditional overlay -> $8800"),
    TileRange("rom0_title_result_tiles0", 0, 0x3839, 0x0500, "TitleResultTileData0 -> queued $8820"),
    TileRange("rom0_title_result_tiles1", 0, 0x3D39, 0x0110, "TitleResultTileData1 -> queued $9140"),
)


def parse_hex(value: str) -> int:
    value = value.strip()
    if value.startswith("$"):
        return int(value[1:], 16)
    return int(value, 0)


def rom_offset(bank: int, address: int) -> int:
    if bank == 0:
        return address
    if address < 0x4000 or address > 0x7FFF:
        raise ValueError(f"ROMX address out of range: bank {bank}, address ${address:04X}")
    return bank * 0x4000 + (address - 0x4000)


def parse_range(spec: str) -> TileRange:
    parts = spec.split(":", 4)
    if len(parts) < 4:
        raise argparse.ArgumentTypeError("range must be NAME:BANK:ADDRESS:SIZE[:NOTE]")
    name, bank, address, size = parts[:4]
    note = parts[4] if len(parts) == 5 else "manual range"
    return TileRange(name, parse_hex(bank), parse_hex(address), parse_hex(size), note)


def decode_tiles(data: bytes, size: int) -> list[list[list[int]]]:
    tile_count = math.ceil(size / 16)
    padded = data[:size].ljust(tile_count * 16, b"\x00")
    tiles: list[list[list[int]]] = []
    for tile_index in range(tile_count):
        base = tile_index * 16
        rows: list[list[int]] = []
        for y in range(8):
            low = padded[base + y * 2]
            high = padded[base + y * 2 + 1]
            row = []
            for bit in range(7, -1, -1):
                row.append(((high >> bit) & 1) << 1 | ((low >> bit) & 1))
            rows.append(row)
        tiles.append(rows)
    return tiles


def render_sheet(
    tiles: list[list[list[int]]],
    palette: tuple[tuple[int, int, int], ...],
    columns: int,
    scale: int,
) -> tuple[int, int, bytearray]:
    rows = math.ceil(len(tiles) / columns) if tiles else 1
    cell = 8 * scale + 1
    width = columns * cell + 1
    height = rows * cell + 1
    grid = (48, 56, 48)
    pixels = bytearray(grid * (width * height))

    for tile_index, tile in enumerate(tiles):
        tile_x = (tile_index % columns) * cell + 1
        tile_y = (tile_index // columns) * cell + 1
        for y, row in enumerate(tile):
            for x, color_index in enumerate(row):
                color = palette[color_index]
                for sy in range(scale):
                    py = tile_y + y * scale + sy
                    for sx in range(scale):
                        px = tile_x + x * scale + sx
                        offset = (py * width + px) * 3
                        pixels[offset : offset + 3] = bytes(color)

    return width, height, pixels


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def write_png(path: Path, width: int, height: int, pixels: bytearray) -> None:
    rows = []
    stride = width * 3
    for y in range(height):
        rows.append(b"\x00" + bytes(pixels[y * stride : (y + 1) * stride]))
    raw = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    image = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(raw, 9))
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(image)


def render_range(
    rom: bytes,
    tile_range: TileRange,
    out_dir: Path,
    palette: tuple[tuple[int, int, int], ...],
    columns: int,
    scale: int,
) -> str:
    offset = rom_offset(tile_range.bank, tile_range.address)
    end = offset + tile_range.size
    if end > len(rom):
        raise ValueError(
            f"{tile_range.name}: ROM range exceeds file size "
            f"(offset ${offset:05X}, size ${tile_range.size:X})"
        )

    tiles = decode_tiles(rom[offset:end], tile_range.size)
    width, height, pixels = render_sheet(tiles, palette, columns, scale)
    out_path = out_dir / f"{tile_range.name}.png"
    write_png(out_path, width, height, pixels)
    return (
        f"| `{out_path.name}` | `${tile_range.bank:02X}` | `${tile_range.address:04X}` "
        f"| `${tile_range.size:04X}` | {len(tiles)} | {tile_range.note} |"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", default="Yoshi/yoshi.gb", help="ROM path")
    parser.add_argument("--out-dir", default="docs/source_recovery/tile_sheets", help="output directory")
    parser.add_argument("--preset", choices=("yoshi-graphics",), help="render a predefined range set")
    parser.add_argument(
        "--range",
        action="append",
        dest="ranges",
        default=[],
        type=parse_range,
        help="range to render as NAME:BANK:ADDRESS:SIZE[:NOTE]",
    )
    parser.add_argument("--columns", type=int, default=16, help="tile columns per sheet")
    parser.add_argument("--scale", type=int, default=3, help="pixel scale")
    parser.add_argument("--palette", choices=sorted(PALETTES), default="dmg")
    args = parser.parse_args()

    selected_ranges: list[TileRange] = []
    if args.preset == "yoshi-graphics":
        selected_ranges.extend(YOSHI_GRAPHICS_RANGES)
    selected_ranges.extend(args.ranges)
    if not selected_ranges:
        parser.error("provide --preset yoshi-graphics or one or more --range values")

    rom_path = Path(args.rom)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rom = rom_path.read_bytes()
    palette = PALETTES[args.palette]

    rows = []
    for tile_range in selected_ranges:
        rows.append(render_range(rom, tile_range, out_dir, palette, args.columns, args.scale))

    manifest = out_dir / "README.md"
    manifest.write_text(
        "# Rendered Game Boy Tile Sheets\n\n"
        f"Source ROM: `{rom_path}`\n\n"
        "Each image decodes 16-byte Game Boy 2bpp tiles in address order. "
        "The grid shows tile boundaries; generated images are evidence aids, "
        "not source assets.\n\n"
        "| File | Bank | Address | Size | Tiles | Notes |\n"
        "|------|------|---------|------|-------|-------|\n"
        + "\n".join(rows)
        + "\n",
        encoding="utf-8",
    )

    print(f"Rendered {len(selected_ranges)} tile sheets into {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
