#!/usr/bin/env python3
"""Enforce the ESP32-S3 static internal-memory release budget from a link map."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import asdict, dataclass


DEFAULT_MINIMUM_INTERNAL_HEADROOM = 192 * 1024
DEFAULT_MAXIMUM_IRAM_SPAN = 96 * 1024

_SEGMENT_RE = re.compile(
    r"^\s*(iram0_0_seg|dram0_0_seg)\s+"
    r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b",
    re.MULTILINE,
)
_SYMBOL_RE = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+"
    r"(_diram_i_start|_iram_start|_iram_end|_heap_low_start)\s+=",
    re.MULTILINE,
)


class MapError(ValueError):
    """The link map does not contain one coherent ESP32-S3 memory layout."""


@dataclass(frozen=True)
class MemoryBudget:
    iram_origin: int
    iram_length: int
    dram_origin: int
    dram_length: int
    diram_i_start: int
    iram_start: int
    iram_end: int
    heap_low_start: int
    dedicated_iram_capacity: int
    iram_span_used: int
    shared_diram_code_used: int
    static_data_used: int
    total_internal_capacity: int
    total_internal_static_used: int
    internal_static_headroom: int

    @property
    def internal_static_used_percent(self) -> float:
        return 100.0 * self.total_internal_static_used / self.total_internal_capacity


def _unique_segments(
    matches: list[tuple[str, str, str]], names: tuple[str, ...]
) -> dict[str, tuple[int, int]]:
    values: dict[str, tuple[int, int]] = {}
    for match in matches:
        name = match[0]
        value = (int(match[1], 16), int(match[2], 16))
        if name in values and values[name] != value:
            raise MapError(f"conflicting {name} definitions")
        values[name] = value
    missing = [name for name in names if name not in values]
    if missing:
        raise MapError("missing map definitions: " + ", ".join(missing))
    return values


def parse_map(text: str) -> MemoryBudget:
    segments_raw = _unique_segments(
        _SEGMENT_RE.findall(text), ("iram0_0_seg", "dram0_0_seg")
    )
    symbols: dict[str, int] = {}
    for address_text, name in _SYMBOL_RE.findall(text):
        address = int(address_text, 16)
        if name in symbols and symbols[name] != address:
            raise MapError(f"conflicting {name} definitions")
        symbols[name] = address
    required_symbols = (
        "_diram_i_start",
        "_iram_start",
        "_iram_end",
        "_heap_low_start",
    )
    missing_symbols = [name for name in required_symbols if name not in symbols]
    if missing_symbols:
        raise MapError("missing map definitions: " + ", ".join(missing_symbols))
    iram_origin, iram_length = segments_raw["iram0_0_seg"]
    dram_origin, dram_length = segments_raw["dram0_0_seg"]
    diram_i_start = symbols["_diram_i_start"]
    iram_start = symbols["_iram_start"]
    iram_end = symbols["_iram_end"]
    heap_low_start = symbols["_heap_low_start"]

    if iram_start != iram_origin:
        raise MapError("_iram_start does not equal iram0_0_seg origin")
    if not iram_origin <= diram_i_start <= iram_origin + iram_length:
        raise MapError("D/IRAM instruction boundary is outside iram0_0_seg")
    if not iram_start <= iram_end <= iram_origin + iram_length:
        raise MapError("IRAM static end is outside iram0_0_seg")
    if not dram_origin <= heap_low_start <= dram_origin + dram_length:
        raise MapError("static DRAM end is outside dram0_0_seg")

    dedicated_capacity = diram_i_start - iram_origin
    iram_span = iram_end - iram_start
    shared_code = max(0, iram_end - diram_i_start)
    data_start = dram_origin + shared_code
    if heap_low_start < data_start:
        raise MapError("static DRAM overlaps shared D/IRAM instruction bytes")
    static_data = heap_low_start - data_start
    total_capacity = dedicated_capacity + dram_length
    total_used = iram_span + static_data
    headroom = total_capacity - total_used
    if headroom < 0:
        raise MapError("combined internal-memory use exceeds physical capacity")

    return MemoryBudget(
        iram_origin=iram_origin,
        iram_length=iram_length,
        dram_origin=dram_origin,
        dram_length=dram_length,
        diram_i_start=diram_i_start,
        iram_start=iram_start,
        iram_end=iram_end,
        heap_low_start=heap_low_start,
        dedicated_iram_capacity=dedicated_capacity,
        iram_span_used=iram_span,
        shared_diram_code_used=shared_code,
        static_data_used=static_data,
        total_internal_capacity=total_capacity,
        total_internal_static_used=total_used,
        internal_static_headroom=headroom,
    )


def evaluate_budget(
    budget: MemoryBudget,
    minimum_internal_headroom: int,
    maximum_iram_span: int,
) -> list[str]:
    failures: list[str] = []
    if budget.internal_static_headroom < minimum_internal_headroom:
        failures.append(
            "internal static headroom "
            f"{budget.internal_static_headroom} is below {minimum_internal_headroom} bytes"
        )
    if budget.iram_span_used > maximum_iram_span:
        failures.append(
            f"IRAM executable span {budget.iram_span_used} exceeds {maximum_iram_span} bytes"
        )
    return failures


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Check the combined ESP32-S3 dedicated IRAM/shared DIRAM static budget. "
            "This intentionally does not interpret the size tool's dedicated 16 KiB "
            "IRAM row as the complete IRAM capacity."
        )
    )
    parser.add_argument("--map", required=True, type=pathlib.Path, dest="map_file")
    parser.add_argument(
        "--minimum-internal-headroom",
        type=int,
        default=DEFAULT_MINIMUM_INTERNAL_HEADROOM,
    )
    parser.add_argument(
        "--maximum-iram-span",
        type=int,
        default=DEFAULT_MAXIMUM_IRAM_SPAN,
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.minimum_internal_headroom < 0 or args.maximum_iram_span <= 0:
        print("memory budget limits must be positive", file=sys.stderr)
        return 2
    try:
        text = args.map_file.read_text(encoding="utf-8", errors="strict")
        budget = parse_map(text)
    except (OSError, UnicodeError, MapError) as error:
        print(f"memory budget parse failed: {error}", file=sys.stderr)
        return 2
    failures = evaluate_budget(
        budget, args.minimum_internal_headroom, args.maximum_iram_span
    )
    if args.json_output:
        result = asdict(budget)
        result["internal_static_used_percent"] = budget.internal_static_used_percent
        result["minimum_internal_headroom"] = args.minimum_internal_headroom
        result["maximum_iram_span"] = args.maximum_iram_span
        result["status"] = "fail" if failures else "pass"
        result["failures"] = failures
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        status = "FAIL" if failures else "PASS"
        print(
            f"memory budget {status}: IRAM span {budget.iram_span_used}/"
            f"{args.maximum_iram_span} B; shared DIRAM code "
            f"{budget.shared_diram_code_used} B; internal static "
            f"{budget.total_internal_static_used}/{budget.total_internal_capacity} B "
            f"({budget.internal_static_used_percent:.2f}%); headroom "
            f"{budget.internal_static_headroom}/{args.minimum_internal_headroom} B minimum"
        )
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
