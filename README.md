# Security Agents

Specialized AI security agents for the PR Security Orchestrator. These agents **do not scan code** — Semgrep, Gitleaks, and diff heuristics already produce findings. Agents validate, prioritize, and remediate those findings **only within PR-changed code**.

## Domains

| Agent | Directory | Focus |
|-------|-----------|-------|
| SQL Injection | `agents/sql-injection/` | Dynamic SQL, parameter binding, ORM misuse |
| Authentication | `agents/authentication/` | Credentials, sessions, identity bypass |
| Authorization | `agents/authorization/` | Access control, privilege escalation |
| XSS | `agents/xss/` | Untrusted output encoding, DOM sinks |
| CSRF | `agents/csrf/` | State-changing request protection |

Each domain contains:

- **agent.md** — Role, scope, behavior, output format
- **skill.md** — Domain expertise and remediation techniques
- **rule.md** — Validation rules, severity, confidence, fix criteria

## Routing

Findings from Semgrep, Gitleaks, and diff heuristics are mapped to agents via `router/mapping.json`. The router loads **only** the selected agent files to minimize token usage.

```bash
python3 router/route.py \
  --agents-dir . \
  --decision ../artifacts/decision.json \
  --payload ../artifacts/cursor_payload.json \
  --output-dir ../artifacts
```

## Outputs

| Artifact | Description |
|----------|-------------|
| `selected_agents.json` | Routed agents, matched findings, routing trace |
| `agent_bundle.md` | Concatenated agent/skill/rule content for Cursor CLI |

## Future

This directory is designed to become the standalone repo `testing-ninja/security-agents`.
