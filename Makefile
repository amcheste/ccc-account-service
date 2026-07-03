IMAGE := ghcr.io/amcheste/ccc-account-service
TAG ?= dev
PLATFORMS := linux/arm64,linux/amd64

.PHONY: build test lint docker docker-multiarch

build:
	go build ./...

test:
	go test ./...

# Requires golangci-lint v2 (config is version "2"):
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
lint:
	golangci-lint run

docker:
	docker build -t $(IMAGE):$(TAG) .

# Requires a buildx builder with arm64 and amd64 support
# (docker buildx create --use, once per machine).
docker-multiarch:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) .
