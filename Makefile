.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.13.0

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: test
test: ## Run the go unit tests
	go test -v -coverprofile=profile.cov -covermode=atomic ./...

integration-test:
	go test -v -coverprofile=profile.cov -covermode=atomic -tags=integration ./...

.PHONY: schema
schema: ## Generate the attestor schema json files
	docker run --rm -v ./:/app -w /app --platform linux/amd64 golang:$(shell awk '/^go / {print $$2}' go.mod) go run ./schemagen/schema.go

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

lint: ## Run the linter
	@golangci-lint run
	@go fmt ./...
	@go vet ./...

.PHONY: check-aws-certs
check-aws-certs: ## Check the AWS public keys used to verify AWS IID documents
	GOWORK=off go run -C ./attestation/aws-iid/check-certs/ . ../aws-certs.go

# vmlinux.h current source:
#   Ubuntu 24.04 LTS kernel, linux-image-unsigned-6.8.0-147-generic (amd64)
#   https://launchpad.net/ubuntu/+archive/primary/+files/linux-image-unsigned-6.8.0-147-generic_6.8.0-147.147_amd64.deb
#   sha256 8f1975936dd8820c9442c2ee7f1d48a5083f316548b3345b14703c8a42c79171
# (bpftool v7.5.0, debian:trixie)
VMLINUX_H := ./attestation/bpf-common/headers/vmlinux.h

# Pinned BPF toolchain and platform to generate byte-identical .o files that are checked on CI.
BPF_BUILDER_IMAGE ?= ghcr.io/cilium/ebpf-builder:1790757212@sha256:f2dad347fb941c1b2cc86ae51697155e2afb020cafb9680fff4f6540069f10f9
BPF_CLANG ?= clang-22
CONTAINER_ENGINE ?= $(if $(shell command -v docker),docker,podman)

.PHONY: generate-bpf
generate-bpf: ## Regenerate all BPF objects and Go bindings with the pinned toolchain (needs docker or podman)
	$(CONTAINER_ENGINE) run --rm --platform linux/amd64 \
		--env GOFLAGS=-buildvcs=false \
		--env BPF2GO_CC=$(BPF_CLANG) --env BPF_CFLAGS="$(BPF_CFLAGS)" \
		-v "$(CURDIR)":/src -w /src \
		$(BPF_BUILDER_IMAGE) \
		go generate ./attestation/commandrun/bpf/... ./attestation/networktrace/bpf/...

.PHONY: generate-bpf-debug
generate-bpf-debug: ## generate with BPF debug logging. Don't commit.
	$(MAKE) generate-bpf BPF_CFLAGS=-DBPF_DEBUG
