#!/usr/bin/env python3
"""Analyze PR compact diff using mapping-driven patterns (no PR-specific hardcoding)."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_changed_ranges(pr_diff_path: Path) -> dict[str, list[tuple[int, int]]]:
    ranges: dict[str, list[tuple[int, int]]] = {}
    if not pr_diff_path.exists():
        return ranges

    current_file = None
    for line in pr_diff_path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True):
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            ranges.setdefault(current_file, [])
        elif line.startswith("@@") and current_file:
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match:
                start = int(match.group(1))
                count = int(match.group(2) or 1)
                ranges[current_file].append((start, start + max(count - 1, 0)))
    return ranges


def resolve_full_path(file_ref: str, changed_ranges: dict[str, list[tuple[int, int]]]) -> str:
    if file_ref in changed_ranges:
        return file_ref
    basename = os.path.basename(file_ref)
    for full_path in changed_ranges:
        if os.path.basename(full_path) == basename:
            return full_path
    return file_ref


def route_patterns(route: dict[str, Any]) -> list[str]:
    patterns: list[str] = []
    match_cfg = route.get("match", {})
    for key in ("type", "summary"):
        patterns.extend(str(p).lower() for p in match_cfg.get(key, []))
    patterns.extend(str(p).lower() for p in route.get("diff_patterns", []))
    return [p for p in patterns if p]


def match_blob(blob: str, patterns: list[str]) -> list[str]:
    return [p for p in patterns if p in blob]


def agent_type_label(agent_id: str) -> str:
    return {
        "sql-injection": "possible_sql_injection",
        "authentication": "possible_authn_weakening",
        "authorization": "possible_authz_bypass",
        "xss": "possible_xss",
        "csrf": "possible_csrf_weakening",
    }.get(agent_id, agent_id)


def analyze_compact_diff(
    compact_path: Path,
    mapping: dict[str, Any],
    changed_ranges: dict[str, list[tuple[int, int]]],
) -> list[dict[str, Any]]:
    if not compact_path.exists():
        return []

    content = compact_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        return []

    routes = [r for r in mapping.get("routes", []) if "diff-heuristic" in r.get("sources", [])]
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    file_blocks: list[tuple[str, list[str]]] = []
    current_basename: str | None = None
    current_lines: list[str] = []

    for line in content.splitlines():
        if line.startswith("FILE:"):
            if current_basename is not None:
                file_blocks.append((current_basename, current_lines))
            current_basename = line.split("FILE:", 1)[1].strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_basename is not None:
        file_blocks.append((current_basename, current_lines))

    for basename, diff_lines in file_blocks:
        if not diff_lines:
            continue

        full_path = resolve_full_path(basename, changed_ranges)
        ranges = changed_ranges.get(full_path, [])
        line_hint = ranges[0][0] if ranges else 0

        added = [ln[1:] for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++")]
        removed = [ln[1:] for ln in diff_lines if ln.startswith("-") and not ln.startswith("---")]
        blob = " ".join(added + removed).lower()

        if not blob.strip():
            continue

        for route in routes:
            agent_id = route.get("agent", "")
            patterns = route_patterns(route)
            hits = match_blob(blob, patterns)
            if not hits:
                continue

            vuln_type = agent_type_label(agent_id)
            key = (full_path, agent_id, vuln_type)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "tool": "diff-heuristic",
                "type": vuln_type,
                "severity": "high",
                "file": full_path,
                "line": line_hint,
                "summary": (
                    f"PR diff in {basename} matches {agent_id} indicators: "
                    f"{', '.join(hits[:3])}"
                )[:200],
                "agent": agent_id,
                "matched_patterns": hits[:5],
            })

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Mapping-driven PR diff security heuristics")
    parser.add_argument("--compact", default="artifacts/pr_compact.diff")
    parser.add_argument("--pr-diff", default="artifacts/pr.diff")
    parser.add_argument("--mapping", default="router/mapping.json")
    parser.add_argument("--output", default="artifacts/diff_security_heuristics.json")
    args = parser.parse_args()

    mapping_path = Path(args.mapping)
    if not mapping_path.exists():
        print(f"ERROR: mapping not found: {mapping_path}", file=sys.stderr)
        return 1

    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    changed_ranges = parse_changed_ranges(Path(args.pr_diff))
    findings = analyze_compact_diff(Path(args.compact), mapping, changed_ranges)

    result = {
        "finding_count": len(findings),
        "findings": findings,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"Diff heuristics written to {output_path}")
    print(json.dumps({"finding_count": len(findings), "agents": sorted({f['agent'] for f in findings})}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
