FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/doris-es-proxy ./cmd/doris-es-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/doris-es-proxy /doris-es-proxy
EXPOSE 9200
ENTRYPOINT ["/doris-es-proxy"]
