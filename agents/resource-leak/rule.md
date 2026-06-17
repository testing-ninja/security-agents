# Resource Leak — Review Rules

## Validation Criteria
- **PR-introduced**: Removed `-` line had active cleanup; `+` line comments it out or deletes it
- **True positive**: Resource acquired in same method/block (connection, statement, stream)
- **In scope**: Changed file appears in PR diff

## Severity Guidance
| Condition | Severity |
|-----------|----------|
| DB connection/statement cleanup disabled in `finally` | Medium |
| File handle cleanup disabled | Medium |
| Cosmetic comment with no live acquire | Low / skip |

## Confidence Scoring
- **High**: Direct pairing `-closeResource(...)` → `+// closeResource(...)`
- **Medium**: Generic `.close()` commented out in `finally`

## Auto-Fix Criteria
Auto-fix when:
- Clear comment-out of existing cleanup in PR diff
- Restore removed lines exactly or use equivalent safe close

Do NOT auto-fix when:
- Cleanup moved to try-with-resources in same hunk (already fixed)
- Refactor replaces manual close with framework-managed lifecycle
