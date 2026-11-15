module github.com/es2doris/doris-es-proxy/e2e/sdkconformance

go 1.25.0

require (
	github.com/elastic/go-elasticsearch/v8 v8.19.7
	github.com/es2doris/doris-es-proxy v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-sql-driver/mysql v1.10.1 // indirect
	go.opentelemetry.io/otel v1.29.0 // indirect
	go.opentelemetry.io/otel/metric v1.29.0 // indirect
	go.opentelemetry.io/otel/trace v1.29.0 // indirect
)

replace github.com/es2doris/doris-es-proxy => ../..
