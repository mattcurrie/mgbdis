#!/usr/bin/env python3
"""Summarize WRAM/HRAM references in the YOSSY NO TAMAGO disassembly."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


DEF_RE = re.compile(r"^DEF\s+([A-Z0-9_]+)\s+EQU\s+\$([0-9a-fA-F]{2,4})")
LABEL_RE = re.compile(r"^([A-Za-z_.$][A-Za-z0-9_.$]*?)::")
HEX_RE = re.compile(r"\$([cC][0-9a-fA-F]{3}|[fF][fF][8-9a-fA-F][0-9a-fA-F])")
BRACKET_NAME_RE = re.compile(r"\[([A-Z0-9_]+)\]")


@dataclass(frozen=True)
class Ref:
    path: str
    line_no: int
    label: str
    text: str
    kind: str


def load_defs(path: Path) -> dict[str, int]:
    defs: dict[str, int] = {}
    for line in path.read_text().splitlines():
        match = DEF_RE.match(line)
        if match:
            defs[match.group(1)] = int(match.group(2), 16)
    return defs


def classify(line: str, token: str) -> str:
    compact = " ".join(line.strip().split())
    if f"ld [{token}]," in compact or f"ldh [{token}]," in compact:
        return "write"
    if f"ld a, [{token}]" in compact or f"ldh a, [{token}]" in compact:
        return "read"
    if f"inc [{token}]" in compact or f"dec [{token}]" in compact:
        return "modify"
    if f"cp [{token}]" in compact or f"or [{token}]" in compact or f"and [{token}]" in compact:
        return "read"
    return "other"


def address_name(address: int, names_by_address: dict[int, list[str]]) -> str:
    names = names_by_address.get(address, [])
    return ", ".join(names) if names else ""


def gather_refs(paths: list[Path], defs: dict[str, int]) -> dict[int, list[Ref]]:
    refs: dict[int, list[Ref]] = defaultdict(list)
    for path in paths:
        label = "(file start)"
        for line_no, line in enumerate(path.read_text().splitlines(), 1):
            label_match = LABEL_RE.match(line)
            if label_match:
                label = label_match.group(1)

            seen: set[tuple[int, str]] = set()

            for match in HEX_RE.finditer(line):
                address = int(match.group(1), 16)
                token = "$" + match.group(1).lower()
                seen.add((address, token))

            for match in BRACKET_NAME_RE.finditer(line):
                name = match.group(1)
                address = defs.get(name)
                if address is not None and (0xC000 <= address <= 0xDFFF or 0xFF80 <= address <= 0xFFFE):
                    seen.add((address, name))

            for address, token in sorted(seen):
                refs[address].append(
                    Ref(
                        path=str(path),
                        line_no=line_no,
                        label=label,
                        text=line.strip(),
                        kind=classify(line, token),
                    )
                )
    return refs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--top", type=int, default=40, help="Number of high-traffic addresses to show")
    args = parser.parse_args()

    root = Path(args.root)
    defs = load_defs(root / "Yoshi" / "constants.inc")
    names_by_address: dict[int, list[str]] = defaultdict(list)
    for name, address in defs.items():
        names_by_address[address].append(name)

    refs = gather_refs(
        [root / "Yoshi" / "bank_000.asm", root / "Yoshi" / "bank_001.asm"],
        defs,
    )

    print("# WRAM/HRAM Reference Summary")
    print()
    print("| Address | Known name | Total | Read | Write | Modify | Other | Sample labels |")
    print("|---------|------------|-------|------|-------|--------|-------|---------------|")
    rows = sorted(refs.items(), key=lambda item: (-len(item[1]), item[0]))[: args.top]
    for address, address_refs in rows:
        counts = defaultdict(int)
        labels: list[str] = []
        for ref in address_refs:
            counts[ref.kind] += 1
            if ref.label not in labels:
                labels.append(ref.label)
        label_text = ", ".join(labels[:5])
        if len(labels) > 5:
            label_text += ", ..."
        print(
            f"| ${address:04X} | {address_name(address, names_by_address)} | {len(address_refs)} | "
            f"{counts['read']} | {counts['write']} | {counts['modify']} | {counts['other']} | {label_text} |"
        )

    print()
    print("## Named Constant Coverage")
    print()
    named_with_refs = [(address, names) for address, names in sorted(names_by_address.items()) if address in refs]
    named_without_refs = [(address, names) for address, names in sorted(names_by_address.items()) if address not in refs]
    print(f"- Named addresses referenced directly or by constant: {len(named_with_refs)}")
    print(f"- Named addresses not seen in bank_000/bank_001 reference scan: {len(named_without_refs)}")
    if named_without_refs:
        print("- Not seen: " + ", ".join(f"${address:04X} ({', '.join(names)})" for address, names in named_without_refs))

    print()
    print("## Detailed High-Traffic Samples")
    for address, address_refs in rows[:10]:
        print()
        print(f"### ${address:04X} {address_name(address, names_by_address)}".rstrip())
        for ref in address_refs[:12]:
            rel = Path(ref.path)
            print(f"- `{rel}:{ref.line_no}` `{ref.label}` [{ref.kind}]: `{ref.text}`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
