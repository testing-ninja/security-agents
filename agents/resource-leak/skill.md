# Resource Leak — Security Skill

## Expertise
CWE-772 (Missing Release of Resource), CWE-400 (Uncontrolled Resource Consumption), JDBC pool exhaustion, Java try-with-resources, finally-block cleanup.

## Analysis Techniques
1. **Diff pairing** — Match removed active `close*` calls with added commented-out equivalents
2. **Context** — Cleanup in `finally` after DB/network operations
3. **Impact** — Repeated requests under load → pool exhaustion → DoS

## Attack / Failure Scenarios
- Commented `closeResource(con)` / `closeResource(statement)` in `finally`
- Removed try-with-resources without replacement
- Swallowed exceptions before cleanup

## Remediation
- Uncomment and restore cleanup calls
- Prefer try-with-resources where the PR already touches the method
- Do not remove legitimate error handling

## Severity
Typically **Medium** for server-side connection leaks under sustained traffic.
