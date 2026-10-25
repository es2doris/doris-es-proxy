# The nix dev shell (flake.nix) provides go, golangci-lint, and security scanners.
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

DORIS_E2E_DSN ?= root:@tcp(127.0.0.1:9030)/?interpolateParams=true&multiStatements=true&timeout=5s&readTimeout=30s&writeTimeout=30s
DORIS_E2E_HTTP ?= http://127.0.0.1:8030

.PHONY: build test test-e2e lint check security scan-vuln scan-sast scan-secrets docker-build compose-up compose-down clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/doris-es-proxy ./cmd/doris-es-proxy

test:
	go test -race -count=1 ./... -v

test-e2e:
	DORIS_E2E_DSN="$(DORIS_E2E_DSN)" DORIS_E2E_HTTP="$(DORIS_E2E_HTTP)" go test -race -count=1 -v ./e2e -run TestLiveApacheDoris_E2E

lint:
	go vet ./...
	golangci-lint run ./...

check: lint test

security: scan-vuln scan-sast scan-secrets

scan-vuln:
	govulncheck ./...

scan-sast:
	gosec -quiet ./...

scan-secrets:
	gitleaks detect --source . --no-git -v

docker-build:
	docker build -t es2doris/doris-es-proxy:latest .

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down -v

clean:
	rm -rf bin dist coverage.out doris-es-proxy
