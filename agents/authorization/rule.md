# Authorization — Review Rules

## Validation Criteria
- Authorization change appears in PR diff
- Finding type/summary matches authz weakening patterns
- Changed endpoint performs sensitive action (write, delete, admin, PII)

## Severity Guidance
| Condition | Severity |
|-----------|----------|
| Unauthenticated write access introduced | Critical |
| Missing role on privileged action | High |
| Public read of non-sensitive resource | Low |

## Confidence Scoring
- **High**: Explicit `permitAll`/`skipAuthorization` in `+` lines
- **Medium**: New endpoint without visible guard in changed class
- **Low**: Scanner hit on unchanged config

## Exploitability Checks
- [ ] Can unauthenticated or low-privilege user invoke changed endpoint?
- [ ] Does PR remove annotation or filter?
- [ ] Is resource ID user-controlled without ownership check?

## Remediation Recommendations
1. Apply least privilege on changed routes
2. Match project’s existing authz annotation style
3. Do not refactor global security architecture

## Auto-Fix Criteria
Auto-fix when:
- Clear `permitAll` or removed `@PreAuthorize` in changed lines
- Project has established pattern for same endpoint type

Do NOT auto-fix when:
- Product decision required for intentionally public API
- Complex RBAC redesign needed
