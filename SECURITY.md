# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `main` / `0.x` | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/es2doris/doris-es-proxy/security/advisories/new).

We pay particular attention to:
- SQL injection or identifier escaping in Query DSL-to-Doris SQL transpilation (`pkg/transpiler`, `pkg/schema`)
- Authentication header handling across Doris FE/BE redirects (`pkg/proxy/streamload.go`)
- Resource exhaustion in `/_bulk` NDJSON streaming and Painless script evaluation (`pkg/esast`, `pkg/painless`)
