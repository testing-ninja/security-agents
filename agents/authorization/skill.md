# Authorization — Security Skill

## Expertise
Spring Security `authorizeHttpRequests`, `@PreAuthorize`, `@Secured`, RBAC, route guards, middleware authz, public vs protected endpoints.

## Analysis Techniques
1. **Policy diff** — Compare `+`/`-` security rules in PR
2. **Endpoint mapping** — New controllers/routes and their required roles
3. **Default deny** — Verify sensitive operations still require authentication + authorization

## Attack Vectors
- `permitAll()` on state-changing endpoints
- Missing role check on admin operations
- IDOR via removed ownership validation in changed code
- `skipAuthorization` / `publicEndpoint` flags

## Exploitability Assessment
| Signal | Risk |
|--------|------|
| New admin action without role check | Critical |
| `permitAll` on POST/PUT/DELETE in diff | High |
| Read-only public GET intentionally added | Context-dependent |

## Remediation Capabilities
- Restore role/scope annotations removed in PR
- Replace broad `permitAll` with specific `hasRole`/`hasAuthority`
- Add ownership checks on changed data access methods

## False Positive Indicators
- Intentional public health/docs endpoint with no sensitive data
- Finding on unchanged security config block
