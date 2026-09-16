FROM golang:1.26.5-bookworm AS build

ARG SERVICE=gateway

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY third_party ./third_party
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o /out/service ./cmd/${SERVICE}

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/service /service
COPY --from=build /src/third_party/coder-websocket-LICENSE.txt /licenses/coder-websocket-LICENSE.txt

USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/service"]
