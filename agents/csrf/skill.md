# CSRF — Security Skill

## Expertise
Spring Security CSRF, synchronizer tokens, SameSite cookies, double-submit cookies, stateless API CSRF exemptions.

## Analysis Techniques
1. **Config diff** — `.csrf().disable()`, `csrf.disable`, `@CsrfExempt` in `+` lines
2. **Endpoint class** — Session-cookie auth + POST/PUT/DELETE without CSRF
3. **Alternative controls** — Bearer-only APIs may not need CSRF if no cookie session

## Attack Vectors
- Global CSRF disable in security config change
- Per-controller CSRF exempt on cookie-authenticated forms
- Missing token on new form POST handlers

## Exploitability Assessment
| Signal | Risk |
|--------|------|
| CSRF disabled + session cookie auth | High |
| Stateless JWT-only API | Lower CSRF risk |
| GET-only public endpoint | Low |

## Remediation Capabilities
- Remove `.csrf().disable()` from changed config
- Remove `@CsrfExempt` unless replaced with equivalent control
- Align with existing project CSRF/token patterns

## False Positive Indicators
- Pure REST API with no cookie session in changed code
- CSRF disable on unchanged lines only
