# Authentication — Security Skill

## Expertise
API keys, passwords, JWT handling, session management, Spring Security auth config, `permitAll` on auth endpoints, trust-all TLS, hardcoded tokens.

## Analysis Techniques
1. **Diff anchoring** — Secret or auth change must be in `+` lines
2. **Context classification** — Production code vs test vs example
3. **Exposure path** — Is value committed, logged, or returned to clients?
4. **Bypass detection** — `setAuthenticated(true)`, disabled filters, trust-all cert managers

## Attack Vectors
- Committed API keys/passwords
- Auth bypass in new endpoints
- Session fixation via weakened checks
- Default credentials in changed config

## Exploitability Assessment
| Signal | Risk |
|--------|------|
| Live-format API key in added line | Critical |
| bcrypt hash in code (may be test data) | Context-dependent |
| Auth check removed in PR | High |

## Remediation Capabilities
- Replace inline secrets with `${ENV_VAR}` or config property references
- Remove secrets from source; add placeholder comments if needed
- Restore authentication guards removed in PR
- Never commit real replacement secrets

## False Positive Indicators
- Finding on unchanged lines far from diff
- Obvious test/mock values with no production path
- Redacted or placeholder strings
