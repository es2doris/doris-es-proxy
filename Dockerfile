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

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/doris-es-proxy ./cmd/doris-es-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/doris-es-proxy /doris-es-proxy
EXPOSE 9200
ENTRYPOINT ["/doris-es-proxy"]
