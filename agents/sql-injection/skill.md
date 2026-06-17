# SQL Injection — Security Skill

## Expertise
Dynamic SQL construction, JDBC/JPA/Hibernate, Spring Data, MyBatis, raw queries, string concatenation in SQL, ORM native queries.

## Analysis Techniques
1. **Source tracing** — Follow user-controlled input from controller/request into repository/DAO in changed lines
2. **Sink identification** — `executeQuery`, `executeUpdate`, `createStatement`, string-formatted SQL, `JdbcTemplate` with concatenation
3. **Diff anchoring** — Confirm vulnerable pattern exists in `+` lines or is directly enabled by PR changes
4. **Parameterization check** — `PreparedStatement`, named parameters, criteria APIs, typed queries

## Attack Vectors
- String concatenation with request parameters
- `String.format` / f-strings in SQL
- Dynamic `WHERE`/`ORDER BY` without allowlists
- Second-order injection via stored values used in new queries

## Exploitability Assessment
| Signal | Higher risk |
|--------|-------------|
| External input reaches SQL in changed code | Yes |
| Only constants/literals in changed SQL | Lower |
| ORM with bound parameters | Usually false positive |
| Changed code removes sanitization | High |

## Remediation Capabilities
- Replace dynamic SQL with `PreparedStatement` and `setString`/`setInt`
- Use `?` placeholders or named parameters
- For dynamic identifiers, use strict allowlists — never parameterize table/column names with user input
- Preserve behavior; avoid refactoring unrelated queries

## False Positive Indicators
- Scanner hit on unchanged legacy code outside diff
- Parameterized query with bound variables only
- Static SQL with no external input in changed hunk
