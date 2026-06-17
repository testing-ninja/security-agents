#!/usr/bin/env python3
"""Route scanner findings to specialized security agents and bundle agent context."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


def load_json(path: str, default: Any = None) -> Any:
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_text(value: Any) -> str:
    return str(value or "").lower()


def finding_text_blob(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("tool", ""),
        finding.get("type", ""),
        finding.get("finding", ""),
        finding.get("summary", ""),
        finding.get("desc", ""),
    ]
    return " ".join(normalize_text(p) for p in parts)


def match_route(finding: dict[str, Any], route: dict[str, Any], source: str) -> bool:
    allowed_sources = route.get("sources", [])
    if allowed_sources and source not in allowed_sources:
        return False

    blob = finding_text_blob(finding)
    match_cfg = route.get("match", {})

    type_patterns = [normalize_text(p) for p in match_cfg.get("type", [])]
    summary_patterns = [normalize_text(p) for p in match_cfg.get("summary", [])]
    all_patterns = type_patterns + summary_patterns

    if not all_patterns:
        return False
    return any(p in blob for p in all_patterns)


def route_finding(
    finding: dict[str, Any],
    mapping: dict[str, Any],
    source: str,
) -> tuple[str, str]:
    """Return (agent_id, match_reason)."""
    agents = mapping.get("agents", {})
    routes = mapping.get("routes", [])
    payload_map = mapping.get("payload_category_map", {})
    default_agent = mapping.get("default_agent", "authentication")

    category = finding.get("finding") or finding.get("type", "")
    if category in payload_map:
        agent_id = payload_map[category]
        if agent_id in agents:
            return agent_id, f"payload_category:{category}"

    for route in routes:
        if match_route(finding, route, source):
            agent_id = route["agent"]
            if agent_id in agents:
                return agent_id, f"route:{route['agent']}"

    return default_agent, "default_fallback"


def collect_findings(decision: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []

    for finding in decision.get("cursor_candidates", []):
        item = dict(finding)
        item["_source"] = finding.get("tool", "decision")
        collected.append(item)

    for finding in payload.get("findings", []):
        item = dict(finding)
        item["_source"] = "cursor_payload"
        collected.append(item)

    if not collected:
        # Allow invocation with PR changes but no candidates — use PR reason
        collected.append({
            "tool": "orchestrator",
            "type": "security_relevant_diff",
            "summary": decision.get("reason", "Security-relevant files modified"),
            "_source": "decision",
        })

    return collected


def read_agent_file(agents_dir: Path, agent_path: str, filename: str) -> str:
    path = agents_dir / agent_path / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def build_agent_bundle(agents_dir: Path, mapping: dict[str, Any], agent_ids: list[str]) -> str:
    agents = mapping.get("agents", {})
    sections: list[str] = [
        "# Security Agent Context",
        "",
        "Load only the agents below. Do not re-scan. Validate scanner findings against PR-changed code only.",
        "",
    ]

    for agent_id in agent_ids:
        meta = agents.get(agent_id, {})
        agent_path = meta.get("path", f"agents/{agent_id}")
        display = meta.get("display_name", agent_id)

        sections.append(f"## Agent: {display} (`{agent_id}`)")
        sections.append("")

        for filename, label in [
            ("agent.md", "Agent Definition"),
            ("skill.md", "Security Skill"),
            ("rule.md", "Review Rules"),
        ]:
            content = read_agent_file(agents_dir, agent_path, filename)
            if content:
                sections.append(f"### {label}")
                sections.append(content)
                sections.append("")

        sections.append("---")
        sections.append("")

    return "\n".join(sections).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Route findings to security agents")
    parser.add_argument("--agents-dir", required=True, help="Path to security-agents repository root")
    parser.add_argument("--decision", default="artifacts/decision.json")
    parser.add_argument("--payload", default="artifacts/cursor_payload.json")
    parser.add_argument("--output-dir", default="artifacts")
    args = parser.parse_args()

    agents_dir = Path(args.agents_dir).resolve()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    mapping_path = agents_dir / "router" / "mapping.json"
    if not mapping_path.exists():
        print(f"ERROR: mapping not found at {mapping_path}", file=sys.stderr)
        return 1

    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    decision = load_json(args.decision, {}) or {}
    payload = load_json(args.payload, {}) or {}

    findings = collect_findings(decision, payload)
    routing_trace: list[dict[str, Any]] = []
    agent_findings: dict[str, list[dict[str, Any]]] = {}
    agent_order: list[str] = []

    for finding in findings:
        source = finding.get("_source", finding.get("tool", "unknown"))
        agent_id, reason = route_finding(finding, mapping, source)

        routing_trace.append({
            "finding": {
                "tool": finding.get("tool"),
                "type": finding.get("type") or finding.get("finding"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "summary": (finding.get("summary") or finding.get("desc", ""))[:200],
            },
            "agent": agent_id,
            "reason": reason,
        })

        agent_findings.setdefault(agent_id, []).append(finding)
        if agent_id not in agent_order:
            agent_order.append(agent_id)

    # Sort agents by configured priority (highest first)
    priority = {
        aid: mapping.get("agents", {}).get(aid, {}).get("priority", 0)
        for aid in agent_order
    }
    agent_order.sort(key=lambda aid: priority.get(aid, 0), reverse=True)

    bundle = build_agent_bundle(agents_dir, mapping, agent_order)

    selected = {
        "repository": str(agents_dir),
        "mapping_version": mapping.get("version"),
        "selected_agents": [
            {
                "id": aid,
                "display_name": mapping.get("agents", {}).get(aid, {}).get("display_name", aid),
                "path": mapping.get("agents", {}).get(aid, {}).get("path"),
                "finding_count": len(agent_findings.get(aid, [])),
            }
            for aid in agent_order
        ],
        "routing_trace": routing_trace,
        "primary_agent": agent_order[0] if agent_order else None,
    }

    selected_path = output_dir / "selected_agents.json"
    bundle_path = output_dir / "agent_bundle.md"

    selected_path.write_text(json.dumps(selected, indent=2), encoding="utf-8")
    bundle_path.write_text(bundle + "\n", encoding="utf-8")

    # Copy loaded agent files for audit trail
    agents_out = output_dir / "loaded_agents"
    agents_out.mkdir(parents=True, exist_ok=True)
    for agent_id in agent_order:
        meta = mapping.get("agents", {}).get(agent_id, {})
        agent_path = meta.get("path", f"agents/{agent_id}")
        dest = agents_out / agent_id
        dest.mkdir(parents=True, exist_ok=True)
        for filename in ("agent.md", "skill.md", "rule.md"):
            content = read_agent_file(agents_dir, agent_path, filename)
            if content:
                (dest / filename).write_text(content + "\n", encoding="utf-8")

    print(f"Selected agents written to {selected_path}")
    print(f"Agent bundle written to {bundle_path}")
    print(json.dumps({
        "primary_agent": selected["primary_agent"],
        "agent_count": len(agent_order),
        "finding_count": len(findings),
        "bundle_chars": len(bundle),
    }, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
