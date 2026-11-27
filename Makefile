# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# The nix dev shell (flake.nix) provides go, golangci-lint, and security scanners.
export GOWORK := off
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

DORIS_E2E_DSN ?= root:@tcp(127.0.0.1:9030)/?interpolateParams=true&timeout=5s&readTimeout=30s&writeTimeout=30s
DORIS_E2E_HTTP ?= http://127.0.0.1:8030

.PHONY: build test test-e2e conformance-fetch test-sdk-conformance test-conformance bench fuzz demo lint check security scan-vuln scan-sast scan-secrets docker-build compose-up compose-down clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/doris-es-proxy ./cmd/doris-es-proxy

demo:
	bash examples/quickstart.sh

test:
	go test -race -count=1 ./... -v

bench:
	go test -bench=. -benchmem -run=^$$ ./pkg/...

FUZZTIME ?= 5s

fuzz:
	go test -fuzz='^FuzzAnalyze$$' -fuzztime=$(FUZZTIME) ./pkg/analysis
	go test -fuzz='^FuzzSpatialH3PolyfillAndGridDisk$$' -fuzztime=$(FUZZTIME) ./pkg/spatial
	go test -fuzz='^FuzzEvalPainless$$' -fuzztime=$(FUZZTIME) ./pkg/painless
	go test -fuzz='^FuzzPainlessEval$$' -fuzztime=$(FUZZTIME) ./pkg/painless
	go test -fuzz='^FuzzPainlessBuiltinsAndRegexBombs$$' -fuzztime=$(FUZZTIME) ./pkg/painless
	go test -fuzz='^FuzzParseESDateMath$$' -fuzztime=$(FUZZTIME) ./pkg/schema
	go test -fuzz='^FuzzInferAndShredDocument$$' -fuzztime=$(FUZZTIME) ./pkg/schema
	go test -fuzz='^FuzzValidateTSDBSettingsAndMappings$$' -fuzztime=$(FUZZTIME) ./pkg/schema
	go test -fuzz='^FuzzShredVariantAndHistogram$$' -fuzztime=$(FUZZTIME) ./pkg/schema
	go test -fuzz='^FuzzShredDocument$$' -fuzztime=$(FUZZTIME) ./pkg/schema
	go test -fuzz='^FuzzVectorAndFlattenedShredder$$' -fuzztime=$(FUZZTIME) ./pkg/schema
	go test -fuzz='^FuzzBulkNDJSONInvariants$$' -fuzztime=$(FUZZTIME) ./pkg/esast
	go test -fuzz='^FuzzUnmarshalSearchRequest$$' -fuzztime=$(FUZZTIME) ./pkg/esast
	go test -fuzz='^FuzzParseBulkNDJSON$$' -fuzztime=$(FUZZTIME) ./pkg/esast
	go test -fuzz='^FuzzLuceneQueryStringBalancedSQL$$' -fuzztime=$(FUZZTIME) ./pkg/transpiler
	go test -fuzz='^FuzzBuildSearchPlanBalancedSQL$$' -fuzztime=$(FUZZTIME) ./pkg/transpiler
	go test -fuzz='^FuzzParseLuceneQueryString$$' -fuzztime=$(FUZZTIME) ./pkg/transpiler
	go test -fuzz='^FuzzBuildSearchPlan$$' -fuzztime=$(FUZZTIME) ./pkg/transpiler
	go test -fuzz='^FuzzNormalizeDorisSQL$$' -fuzztime=$(FUZZTIME) ./pkg/transpiler
	go test -fuzz='^FuzzJSONPathAndNestedSQLSafety$$' -fuzztime=$(FUZZTIME) ./pkg/transpiler
	go test -fuzz='^FuzzCompileGrokAndDissect$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzRenderMustacheTemplate$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzDecompressRequestBody$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzNormalizeDorisSQL$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzStreamLoadRedirect$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzExtractIngestAttachment$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzESQLAndEQL$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzSpatialWKTGeoJSONAndGrid$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzTermsEnumDLSFLS$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzWireMiddlewareYAMLHead$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzRepositoryURLValidator$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzExpandIngestTemplate$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzStrictNereidsSQLGuards$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzHistogramBoundsAndSQL$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzMonitoringBulkNDJSON$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzAutoscalingByteSize$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzSQLAndFullESQLEQLEval$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzHistogramGapFillAndTimeZones$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzQueryAndShardCacheKeyIsolation$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzStreamLoadChunkingHeadersAndErrorURL$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzRound66SecurityConnectorInferenceHandlers$$' -fuzztime=$(FUZZTIME) ./pkg/proxy
	go test -fuzz='^FuzzFilterPathGlobAndSourceQueryParam$$' -fuzztime=$(FUZZTIME) ./pkg/proxy

test-e2e:
	DORIS_E2E_DSN="$(DORIS_E2E_DSN)" DORIS_E2E_HTTP="$(DORIS_E2E_HTTP)" go test -race -count=1 -v ./e2e -run TestLiveApacheDoris_E2E

conformance-fetch:
	bash scripts/fetch-conformance-specs.sh

test-sdk-conformance:
	go -C e2e/sdkconformance test -race -count=1 -v ./...

test-conformance:
	bash scripts/fetch-conformance-specs.sh
	CONFORMANCE_REQUIRE_UPSTREAM=1 CONFORMANCE_MIN_V7_PASSED=1995 CONFORMANCE_MIN_V8_PASSED=4675 go test -race -count=1 -v ./pkg/compliance -run 'TestUpstream|TestSpecSchemaValidatorLiveUpstreamSchema'
	go -C e2e/sdkconformance test -race -count=1 -v ./...

lint:
	gofmt -s -w .
	go vet ./...
	golangci-lint run ./...

check: lint test

GOVULNCHECK_TOOLCHAIN ?= go1.26.11+auto

security: scan-vuln scan-sast scan-secrets

scan-vuln:
	GOTOOLCHAIN=$(GOVULNCHECK_TOOLCHAIN) govulncheck ./...

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
