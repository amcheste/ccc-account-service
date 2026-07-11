IMAGE := ghcr.io/amcheste/ccc-account-service
TAG ?= dev
PLATFORMS := linux/arm64,linux/amd64
KIND_CLUSTER := ccc
KIND_CONTEXT := kind-$(KIND_CLUSTER)

.PHONY: build test test-integration lint docker docker-multiarch kind-up kind-deploy kind-down

build:
	go build ./...

test:
	go test ./...

# Store tests against a real Postgres via testcontainers; needs a
# running Docker daemon.
test-integration:
	go test -tags integration ./internal/store/...

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

# ── Local kind cluster ───────────────────────────────────────────────
# kind-up:     create the cluster (idempotent) and deploy the service.
# kind-deploy: rebuild the image and roll it onto the running cluster;
#              safe to re-run after every code change.
# kind-down:   delete the cluster.

kind-up:
	@kind get clusters 2>/dev/null | grep -qx '$(KIND_CLUSTER)' || \
		kind create cluster --name $(KIND_CLUSTER)
	$(MAKE) kind-deploy

kind-deploy: docker
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER)
	kubectl --context $(KIND_CONTEXT) apply -k deploy/kind
	kubectl --context $(KIND_CONTEXT) -n ccc rollout restart deploy/account-service
	kubectl --context $(KIND_CONTEXT) -n ccc rollout status deploy/account-service --timeout=120s
	@echo ""
	@echo "account-service is up. Try:"
	@echo "  kubectl --context $(KIND_CONTEXT) -n ccc port-forward deploy/account-service 8081:8081 &"
	@echo "  curl localhost:8081/healthz"

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)
