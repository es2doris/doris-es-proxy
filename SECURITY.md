# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `v0.15.x` / `main` | :white_check_mark: |
| `< v0.15.0` | :x: |

## Reporting a Vulnerability

Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/es2doris/doris-es-proxy/security/advisories/new). We aim to acknowledge reports within 48 hours and publish a patched release within 7 days for critical issues.

We pay particular attention to:
- SQL injection or identifier escaping in Query DSL-to-Doris SQL transpilation (`pkg/transpiler`, `pkg/schema`)
- Authentication header handling across Doris FE/BE redirects (`pkg/proxy/streamload.go`)
- Inbound HTTP authentication (`Basic` / `ApiKey` / `Bearer`), RBAC, Field-Level Security, and Row-Level Security (`pkg/proxy/features.go`)
- Resource exhaustion in `/_bulk` NDJSON streaming, request body size limits (`DefaultMaxRequestBodyBytes`), and Painless script evaluation (`pkg/esast`, `pkg/painless`)
