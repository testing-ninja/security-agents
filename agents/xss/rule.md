# XSS — Review Rules

## Validation Criteria
- Sink or missing encoding in PR-changed hunk
- Data reaching sink is plausibly user-controlled
- Finding intersects diff (±5 lines)

## Severity Guidance
| Condition | Severity |
|-----------|----------|
| Stored XSS via new persistence + render | High |
| Reflected XSS in new endpoint output | High |
| Static HTML change, no user data | Info |

## Confidence Scoring
- **High**: Direct user input to raw HTML sink in `+` lines
- **Medium**: Indirect data flow visible in diff
- **Low**: Scanner hit outside changed output path

## Exploitability Checks
- [ ] Can attacker supply payload via changed code path?
- [ ] Is output interpreted as HTML/JS?
- [ ] Are existing encoders bypassed in PR?

## Remediation Recommendations
1. Encode for output context
2. Avoid raw HTML APIs for untrusted data
3. Minimal change to changed template/component only

## Auto-Fix Criteria
Auto-fix when:
- Obvious `innerHTML`/raw write with variable in changed lines
- Standard escape API exists in same file/framework

Do NOT auto-fix when:
- Requires CSP or architectural HTML strategy
- Rich HTML intentionally needed — needs sanitizer selection
