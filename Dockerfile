# syntax=docker/dockerfile:1
# Multi-arch build: cross-compiles on the build host, so `docker buildx
# build --platform linux/arm64,linux/amd64` produces both images without
# emulation. CGO stays disabled; keep it that way.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/account-service ./cmd/account-service

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/account-service /account-service
EXPOSE 8080 8081 9090
USER nonroot
ENTRYPOINT ["/account-service"]
