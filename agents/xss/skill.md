# XSS — Security Skill

## Expertise
Reflected/stored/DOM XSS, HTML escaping, CSP, React `dangerouslySetInnerHTML`, JSP/Thymeleaf escaping, `document.write`, servlet writers.

## Analysis Techniques
1. **Sink analysis** — Changed lines writing HTML/JS to DOM or response
2. **Source tracing** — Request params, DB fields, user content in new code
3. **Context** — HTML attribute, JS string, URL — encoding must match context
4. **Framework defaults** — Auto-escape templates vs raw output APIs

## Attack Vectors
- `innerHTML = userInput` in added JS/TS
- Unescaped `${}` or `th:utext` on untrusted data
- `response.getWriter().write(userData)` without encoding

## Exploitability Assessment
| Signal | Risk |
|--------|------|
| Raw user input → HTML sink in `+` lines | High |
| Static trusted markup only | Low |
| Framework auto-escape with no bypass | False positive |

## Remediation Capabilities
- Use `textContent` instead of `innerHTML`
- Apply framework escape functions
- Remove `dangerouslySetInnerHTML` where possible
- Use structured APIs (React children) instead of HTML strings

## False Positive Indicators
- Encoded output in changed code
- Constant literals only in sink
- Finding on unchanged template
