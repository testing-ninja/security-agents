# SQL Injection — Review Rules

## Validation Criteria
- **PR-introduced**: Vulnerable pattern must appear in added/changed lines or be enabled by PR (e.g., new parameter wired into query)
- **True positive**: Untrusted data can reach SQL execution without binding/parameterization
- **In scope**: File and line referenced by finding intersect changed diff hunks (±5 lines)

## Severity Guidance
| Condition | Severity |
|-----------|----------|
| User input → raw SQL in changed code | High |
| Internal constant concatenation only | Medium/Low |
| ORM parameterized query | Info — likely false positive |

## Confidence Scoring
- **High (0.9+)**: Clear concatenation/format of external input in `+` lines
- **Medium (0.6–0.9)**: Indirect flow; input path plausible from diff
- **Low (<0.6)**: Finding on unchanged context; auto-fix only if high confidence

## Exploitability Checks
- [ ] Is input attacker-controlled (HTTP, message, file upload)?
- [ ] Does changed code pass it into SQL string building?
- [ ] Is there a code path from new/changed endpoint to the sink?

## Remediation Recommendations
1. Use prepared statements with bound parameters
2. Never embed user input in SQL structure (identifiers, ORDER BY)
3. Keep fix localized to changed method/hunk
4. Do not rewrite entire repository data layer

## Auto-Fix Criteria
Apply fix automatically when:
- Confidence ≥ 0.8
- Sink and fix are within allowed changed files
- Parameterization is straightforward (single query, obvious variables)

Do NOT auto-fix when:
- Requires schema or API redesign
- Dynamic identifiers need allowlist design not evident from diff
- Finding is outside changed hunks
