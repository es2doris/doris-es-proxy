# The nix dev shell (flake.nix) provides go, golangci-lint, and security scanners.
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

DORIS_E2E_DSN ?= root:@tcp(127.0.0.1:9030)/?interpolateParams=true&multiStatements=true&timeout=5s&readTimeout=30s&writeTimeout=30s
DORIS_E2E_HTTP ?= http://127.0.0.1:8030

.PHONY: build test test-e2e bench fuzz demo lint check security scan-vuln scan-sast scan-secrets docker-build compose-up compose-down clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/doris-es-proxy ./cmd/doris-es-proxy

demo:
	bash examples/quickstart.sh

test:
	go test -race -count=1 ./... -v

bench:
	go test -bench=. -benchmem -run=^$$ ./pkg/...

fuzz:
	go test -fuzz=FuzzBuildSearchPlan -fuzztime=5s ./pkg/transpiler
	go test -fuzz=FuzzEvalPainless -fuzztime=5s ./pkg/painless
	go test -fuzz=FuzzShredDocument -fuzztime=5s ./pkg/schema
	go test -fuzz=FuzzParseBulkNDJSON -fuzztime=5s ./pkg/esast

test-e2e:
	DORIS_E2E_DSN="$(DORIS_E2E_DSN)" DORIS_E2E_HTTP="$(DORIS_E2E_HTTP)" go test -race -count=1 -v ./e2e -run TestLiveApacheDoris_E2E

lint:
	gofmt -s -w .
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
