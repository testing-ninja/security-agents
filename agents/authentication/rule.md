# Authentication — Review Rules

## Validation Criteria
- Finding file/line near changed hunk (±5 lines) or in newly added file
- Gitleaks: entropy/format match alone insufficient — must be in PR-introduced content
- Auth weakening: pattern must be in added lines

## Severity Guidance
| Condition | Severity |
|-----------|----------|
| Live API key/password in new code | Critical |
| Auth bypass introduced | High |
| Test fixture secret in test file only | Low |

## Confidence Scoring
- **High**: Recognizable secret format in `+` line with production path
- **Medium**: Hash/token in changed code; purpose unclear
- **Low**: Scanner hit outside diff context

## Exploitability Checks
- [ ] Would merged code expose credential to repository readers?
- [ ] Does PR disable or skip authentication?
- [ ] Is secret used in runtime path introduced by PR?

## Remediation Recommendations
1. Remove hardcoded values; use environment or vault references
2. Re-enable authentication/validation removed in PR
3. Do not add new secrets to the codebase

## Auto-Fix Criteria
Auto-fix when:
- Clear hardcoded secret in changed line → replace with env reference pattern used in project
- Obvious auth guard removed in PR → restore minimal guard

Do NOT auto-fix when:
- Requires secret rotation coordination
- Unclear if value is test data
- Finding outside PR changes
