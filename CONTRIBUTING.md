# Contributing to `doris-es-proxy`

Thank you for contributing to `doris-es-proxy`!

## Development Environment

This repository uses a Nix flake (`flake.nix`) for reproducible tooling (`go`, `golangci-lint`, `lefthook`, `govulncheck`, `gosec`, `gitleaks`).

```bash
# Run tests inside the Nix dev shell
nix develop -c go test -race -count=1 ./... -v

# Run linters
nix develop -c golangci-lint run ./...

# Run full verification suite (gofmt, vet, race tests, SAST)
nix develop -c make check

# Run live Apache Doris 4.x E2E test suite (requires Docker + DORIS_DSN / DORIS_HTTP)
DORIS_DSN="root:@tcp(127.0.0.1:9030)/?interpolateParams=true" DORIS_HTTP="http://127.0.0.1:8030" \
  nix develop -c go test -v -race ./e2e/...
```

## Commit & License Conventions

1. **Conventional Commits:** Commit messages must follow Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`).
2. **DCO Sign-Off:** Sign off commits with `git commit -s` (`Signed-off-by:`) and keep the Apache-2.0 license header on all `.go` files.
3. **Pre-Commit Hooks:** Never bypass git hooks (`--no-verify`).
