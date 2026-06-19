#!/usr/bin/env python3
"""Parse external HTTP/3 interop JSONL results into a Markdown matrix."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


STATUS_MARKS = {
    "pass": "PASS",
    "fail": "FAIL",
    "blocked": "BLOCKED",
    "skip": "SKIP",
    "error": "ERROR",
}


def load_results(path: Path) -> list[dict]:
    results: list[dict] = []
    if not path.exists():
        raise FileNotFoundError(path)

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return results


def render_markdown(results: list[dict]) -> str:
    scenarios = sorted({str(row.get("scenario", "")) for row in results if row.get("scenario")})
    targets = sorted({str(row.get("target", "")) for row in results if row.get("target")})
    by_key = {(str(row.get("target")), str(row.get("scenario"))): row for row in results}
    counts: defaultdict[str, int] = defaultdict(int)
    for row in results:
        counts[str(row.get("status", "unknown"))] += 1

    lines: list[str] = [
        "# External HTTP/3 Interop Report",
        "",
        "This report is generated from JSONL results produced by the external HTTP/3 interop harness.",
        "",
        "## Summary",
        "",
        f"- Total results: {len(results)}",
    ]

    for status in sorted(counts):
        lines.append(f"- {status}: {counts[status]}")

    lines.extend(["", "## Matrix", ""])
    header = ["Target", *scenarios]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join(["---"] * len(header)) + " |")

    for target in targets:
        cells = [target]
        for scenario in scenarios:
            row = by_key.get((target, scenario))
            if row is None:
                cells.append("")
                continue
            status = str(row.get("status", "unknown"))
            cells.append(STATUS_MARKS.get(status, status.upper()))
        lines.append("| " + " | ".join(cells) + " |")

    lines.extend(["", "## Details", ""])
    for row in sorted(results, key=lambda item: (str(item.get("target")), str(item.get("scenario")))):
        target = row.get("target", "")
        scenario = row.get("scenario", "")
        status = row.get("status", "unknown")
        detail = row.get("detail", "")
        artifact = row.get("artifact", "")
        lines.append(f"### {target} / {scenario}")
        lines.append("")
        lines.append(f"- Status: {status}")
        if detail:
            lines.append(f"- Detail: {detail}")
        if artifact:
            lines.append(f"- Artifact: `{artifact}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, help="Path to results.jsonl")
    parser.add_argument("-o", "--output", type=Path, help="Path to write Markdown report")
    args = parser.parse_args()

    markdown = render_markdown(load_results(args.results))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
