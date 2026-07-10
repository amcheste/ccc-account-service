<div align="center">

# ccc-account-service

**Identity, credentials, and token issuance for the Command and Control Center.**

[![Validate](https://github.com/amcheste/ccc-account-service/actions/workflows/validate.yml/badge.svg)](https://github.com/amcheste/ccc-account-service/actions/workflows/validate.yml)
[![Version](https://img.shields.io/github/v/tag/amcheste/ccc-account-service?label=version&sort=semver&color=0B0B0C)](https://github.com/amcheste/ccc-account-service/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-1F4D3A.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/amcheste/ccc-account-service/badge)](https://scorecard.dev/viewer/?uri=github.com/amcheste/ccc-account-service)

</div>

---

The account service is the first CCC microservice: username/password
authentication issuing short-lived Ed25519 JWTs, rotated refresh
tokens, and coarse household roles. Full design, including everything
this skeleton does not implement yet, lives in
[docs/design/account-service.md](docs/design/account-service.md).

## Surfaces

| Port | Protocol | Audience |
|------|----------|----------|
| 8080 | REST/JSON | web frontend, via ingress |
| 9090 | gRPC (`ccc.account.v1`) | other CCC services |
| 8081 | HTTP ops | kubelet probes, Prometheus |

The gRPC contract is defined in
[ccc-protos](https://github.com/amcheste/ccc-protos); this repo
consumes the generated module at a tagged release.

## Development

```sh
make build            # compile everything
make test             # unit tests
make lint             # golangci-lint, same config as CI
make docker           # local single-arch image
make docker-multiarch # linux/arm64 + linux/amd64 manifest via buildx
```

Runs on Go 1.26, CGO disabled everywhere. Keep it that way: the
multi-arch build cross-compiles and any CGO dependency breaks it.

### Local cluster (kind)

```sh
make kind-up      # create the ccc kind cluster and deploy the service
make kind-deploy  # rebuild and roll the image after a code change
make kind-down    # tear it all down
```

`kind-up` is idempotent and ends with the pod ready; it prints the
port-forward and curl commands for hitting `/healthz`. The
`deploy/kind` overlay pins one replica and the `dev` image tag; it is
the only overlay that lives in this repo because it targets a
throwaway local cluster, not the homelab.

## Deployment

`deploy/base/` is a generic kustomize base: probes, ports, resource
envelope sized for Pi 5 nodes, and nothing cluster-specific. The
private ccc-deploy repo overlays it with namespace, image pins,
ingress, and sealed secrets. If a value would change when someone else
deployed this service, it does not belong in this repo.
