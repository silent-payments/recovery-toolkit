"""Minimal stderr-summary helpers for the sp_* scripts.

Stdlib only.  Stdout is reserved for the JSON pipeline contract between
sp_derive | sp_scan | sp_sign, so every helper here writes to stderr
(or any file-like passed in) and never touches stdout.
"""
import sys
from typing import Iterable, Optional, Sequence, Tuple


def _resolve(file):
    return sys.stderr if file is None else file


def _normalize_align(align: Optional[Sequence[str]], n: int) -> list:
    if align is None:
        return ["l"] * n
    if len(align) != n:
        raise ValueError(f"align length {len(align)} != column count {n}")
    return list(align)


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence],
    align: Optional[Sequence[str]] = None,
    file=None,
) -> None:
    """Render a fixed-width ASCII table.  `align` is per-column,
    'r' for right-justified, anything else for left."""
    out = _resolve(file)
    headers = [str(h) for h in headers]
    rows = [[str(c) for c in r] for r in rows]
    n = len(headers)
    aligns = _normalize_align(align, n)
    widths = [len(h) for h in headers]
    for r in rows:
        if len(r) != n:
            raise ValueError(f"row has {len(r)} cells, expected {n}")
        for i, c in enumerate(r):
            if len(c) > widths[i]:
                widths[i] = len(c)

    def line(cells, cell_aligns):
        return "  ".join(
            c.rjust(w) if a == "r" else c.ljust(w)
            for c, w, a in zip(cells, widths, cell_aligns)
        ).rstrip()

    total = sum(widths) + 2 * (n - 1)
    out.write(line(headers, ["l"] * n) + "\n")
    out.write("─" * total + "\n")
    for r in rows:
        out.write(line(r, aligns) + "\n")
    out.flush()


def kv(
    pairs: Iterable[Tuple[str, object]],
    indent: int = 2,
    file=None,
) -> None:
    """Render aligned `key : value` pairs."""
    out = _resolve(file)
    pairs = [(str(k), str(v)) for k, v in pairs]
    if not pairs:
        return
    key_w = max(len(k) for k, _ in pairs)
    pad = " " * indent
    for k, v in pairs:
        out.write(f"{pad}{k.ljust(key_w)} : {v}\n")
    out.flush()


def section(title: str, file=None) -> None:
    """Blank line + section title."""
    out = _resolve(file)
    out.write(f"\n{title}\n")
    out.flush()
