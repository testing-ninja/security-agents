# CSRF — Review Rules

## Validation Criteria
- CSRF weakening appears in PR diff (`+` lines)
- Affected routes use session/cookie authentication
- State-changing HTTP methods involved

## Severity Guidance
| Condition | Severity |
|-----------|----------|
| Global CSRF off in PR | High |
| Exempt on cookie-auth form POST | High |
| Stateless token API only | Info — may be acceptable |

## Confidence Scoring
- **High**: Explicit disable/exempt in changed security config
- **Medium**: New POST handler without visible CSRF in cookie-auth app
- **Low**: Finding outside diff

## Exploitability Checks
- [ ] Does app rely on session cookies for auth?
- [ ] Can cross-site form/request trigger state change?
- [ ] Did PR remove token validation?

## Remediation Recommendations
1. Re-enable CSRF for cookie-session apps
2. Use framework CSRF token support
3. Do not blanket-disable CSRF in PR

## Auto-Fix Criteria
Auto-fix when:
- `.csrf().disable()` added in changed config block
- `@CsrfExempt` added without documented alternative

Do NOT auto-fix when:
- Architecture is intentionally stateless with bearer tokens only
- Requires product decision on exemption scope
