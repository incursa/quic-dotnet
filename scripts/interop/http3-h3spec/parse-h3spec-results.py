#!/usr/bin/env python3
"""Parse h3spec stdout/stderr into JSON and Markdown triage artifacts."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


CASE_LINE = re.compile(r"^\s{2,}(?P<name>MUST .+?)(?:\s+(?P<status>FAILED)\s+\[(?P<failure_id>\d+)])?\s*$")
FAILURE_LINE = re.compile(r"^\s*(?P<failure_id>\d+)\)\s+(?P<suite>.+?)\s+(?P<name>MUST .+)$")
SUMMARY_LINE = re.compile(r"(?P<total>\d+)\s+examples?,\s+(?P<failures>\d+)\s+failures?")
SECTION_TOKEN = re.compile(r"\[(?P<family>HTTP/3|QPACK|Transport|TLS)\s+(?P<section>[^\]]+)]")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
CASE_MARKER_SUFFIX = re.compile(r"\s+\[[xv]]\s*$")
RERUN_LINE = re.compile(r"^\s*To rerun use:\s+(?P<rerun>.+)$")

RFC_BY_FAMILY = {
    "HTTP/3": "RFC 9114",
    "QPACK": "RFC 9204",
    "Transport": "RFC 9000",
    "TLS": "RFC 9001",
}

GAP_BY_RFC = {
    "RFC 9114": "http3-adapter-boundary",
    "RFC 9204": "qpack-stream-state-boundary",
}


def read_text(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_case_reference(name: str) -> dict[str, str]:
    match = SECTION_TOKEN.search(name)
    if not match:
        return {
            "family": "unknown",
            "rfc": "unknown",
            "section": "",
            "requirement": "unmapped",
            "gap": "",
        }

    family = match.group("family")
    section = match.group("section")
    rfc = RFC_BY_FAMILY.get(family, "unknown")
    return {
        "family": family,
        "rfc": rfc,
        "section": section,
        "requirement": f"{rfc} Section {section}" if rfc != "unknown" else "unmapped",
        "gap": GAP_BY_RFC.get(rfc, ""),
    }


def normalize_case_name(name: str) -> str:
    return CASE_MARKER_SUFFIX.sub("", name).strip()


def parse_stdout(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    failures_by_id: dict[str, dict[str, str]] = {}
    failures_by_name: dict[tuple[str, str], dict[str, str]] = {}
    current_failure: dict[str, str] | None = None
    current_suite = ""
    summary: dict[str, Any] = {
        "total": 0,
        "failures": 0,
    }

    for line in stdout.splitlines():
        line = ANSI_ESCAPE.sub("", line)
        stripped = line.strip()

        if current_failure is not None:
            rerun_match = RERUN_LINE.match(line)
            if rerun_match:
                current_failure["rerun"] = rerun_match.group("rerun").strip()
                current_failure = None
            elif stripped and not FAILURE_LINE.match(line):
                detail = current_failure.get("detail", "")
                current_failure["detail"] = f"{detail}\n{stripped}".strip()

        if stripped and not line.startswith(" ") and not stripped.startswith("Finished") and "examples," not in stripped:
            current_suite = stripped

        case_match = CASE_LINE.match(line)
        if case_match:
            name = case_match.group("name").strip()
            ref = parse_case_reference(name)
            cases.append(
                {
                    "suite": current_suite,
                    "name": name,
                    "status": "fail" if case_match.group("status") else "pass",
                    "failureId": case_match.group("failure_id") or "",
                    **ref,
                }
            )
            continue

        failure_match = FAILURE_LINE.match(line)
        if failure_match:
            failure = {
                "suite": failure_match.group("suite").strip(),
                "name": failure_match.group("name").strip(),
                "detail": "",
            }
            failures_by_id[failure_match.group("failure_id")] = failure
            failures_by_name[
                (failure["suite"], normalize_case_name(failure["name"]))
            ] = failure
            current_failure = failure
            continue

        summary_match = SUMMARY_LINE.search(line)
        if summary_match:
            summary["total"] = int(summary_match.group("total"))
            summary["failures"] = int(summary_match.group("failures"))

    for case in cases:
        failure_id = case.get("failureId", "")
        if failure_id in failures_by_id:
            case["status"] = "fail"
            case["failureDetail"] = failures_by_id[failure_id].get("detail", "")
            case["rerun"] = failures_by_id[failure_id].get("rerun", "")
            continue

        failure = failures_by_name.get((case["suite"], normalize_case_name(case["name"])))
        if failure is not None:
            case["status"] = "fail"
            case["failureDetail"] = failure.get("detail", "")
            case["rerun"] = failure.get("rerun", "")

    if summary["total"] == 0 and cases:
        summary["total"] = len(cases)
        summary["failures"] = sum(1 for case in cases if case["status"] == "fail")

    return cases, summary


def load_metadata(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_result(stdout: str, stderr: str, metadata: dict[str, Any]) -> dict[str, Any]:
    cases, summary = parse_stdout(stdout)
    exit_code = metadata.get("exitCode")
    requested_matches = metadata.get("match", [])
    requested_skips = metadata.get("skip", [])
    selected_cases = len(cases)
    selection_status = "unfiltered"
    if requested_matches:
        selection_status = "filtered" if selected_cases else "no-selected-cases"

    if exit_code is None:
        status = "not-run"
    elif selection_status == "no-selected-cases":
        status = "no-selected-cases"
    elif int(exit_code) == 0 and summary["failures"] == 0:
        status = "pass"
    else:
        status = "fail"

    summary.update(
        {
            "status": status,
            "exitCode": exit_code,
            "selectedCases": selected_cases,
            "selectionStatus": selection_status,
            "requestedMatchCount": len(requested_matches),
            "requestedSkipCount": len(requested_skips),
            "rerunSuggestions": sum(1 for case in cases if case.get("rerun")),
            "http3OrQpackFailures": sum(
                1
                for case in cases
                if case["status"] == "fail" and case["rfc"] in {"RFC 9114", "RFC 9204"}
            ),
            "stderrBytes": len(stderr.encode("utf-8")),
        }
    )

    return {
        "tool": "h3spec",
        "metadata": metadata,
        "summary": summary,
        "cases": cases,
        "failures": [case for case in cases if case["status"] == "fail"],
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    metadata = result.get("metadata", {})
    lines = [
        "# h3spec HTTP/3 Server Triage Report",
        "",
        "This report is generated from h3spec stdout/stderr. It is a conformance triage artifact, not a broad support claim.",
        "",
        "## Summary",
        "",
        f"- Status: {summary['status']}",
        f"- Exit code: {summary['exitCode']}",
        f"- Cases: {summary['total']}",
        f"- Selected cases: {summary['selectedCases']}",
        f"- Selection status: {summary['selectionStatus']}",
        f"- Failures: {summary['failures']}",
        f"- RFC 9114/RFC 9204 failures: {summary['http3OrQpackFailures']}",
        f"- Host: {metadata.get('host', '')}",
        f"- Port: {metadata.get('port', '')}",
        "",
    ]

    requested_matches = metadata.get("match", [])
    if requested_matches:
        lines.extend(["## Requested Matches", ""])
        for item in requested_matches:
            lines.append(f"- `{item}`")
        lines.append("")

    if summary["selectionStatus"] == "no-selected-cases":
        lines.extend(
            [
                "## Selection Warning",
                "",
                "The requested match filters selected no h3spec cases. Treat this run as tooling evidence only, not conformance evidence.",
                "",
            ]
        )

    lines.extend(["## Failing Cases", ""])

    failures = result["failures"]
    if failures:
        lines.append("| Case | RFC Mapping | Gap / Requirement Home | Follow-up TODO |")
        lines.append("| --- | --- | --- | --- |")
        for case in failures:
            mapping = case["requirement"]
            gap = case["gap"] or "outside RFC 9114/RFC 9204 mapping"
            todo = f"Create or update a protocol-owned requirement/test for `{case['name']}`."
            detail = case.get("failureDetail", "").replace("|", "\\|")
            lines.append(f"| {case['name']} | {mapping} | {gap}: {detail} | TODO: {todo} |")
    else:
        lines.append("No failing cases were parsed.")

    lines.extend(["", "## All Parsed Cases", ""])
    if result["cases"]:
        lines.append("| Status | Suite | Case | RFC Mapping |")
        lines.append("| --- | --- | --- | --- |")
        for case in result["cases"]:
            lines.append(f"| {case['status']} | {case['suite']} | {case['name']} | {case['requirement']} |")
    else:
        lines.append("No h3spec cases were parsed. If this was not a plan-only run, inspect stdout/stderr.")

    lines.extend(["", "## TODO Items", ""])
    for case in failures:
        if case["rfc"] in {"RFC 9114", "RFC 9204"}:
            lines.append(f"- [ ] `{case['requirement']}`: triage h3spec failure `{case['name']}` under `{case['gap']}`.")

    if not any(case["rfc"] in {"RFC 9114", "RFC 9204"} for case in failures):
        lines.append("- [ ] No RFC 9114/RFC 9204 h3spec failures parsed in this run.")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()

    result = build_result(read_text(args.stdout), read_text(args.stderr), load_metadata(args.metadata))
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    args.markdown_output.write_text(render_markdown(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
