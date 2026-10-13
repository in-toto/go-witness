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

# ── Pinned inputs for BPF generation ─────────────────────────────────────────
# Everything that affects the generated objects/bindings is pinned here, so the
# output is identical on any machine. Change these only deliberately.
#
# Platform: both images run as linux/amd64 everywhere (natively on x86,
# emulated elsewhere), so every machine runs the same binaries.
BPF_PLATFORM ?= linux/amd64
# Toolchain: clang/LLVM, Go, bpf2go's libbpf headers and the bpftool used to
# write vmlinux.h.
BPF_BUILDER_IMAGE ?= ghcr.io/cilium/ebpf-builder:1790757212@sha256:f2dad347fb941c1b2cc86ae51697155e2afb020cafb9680fff4f6540069f10f9
BPF_CLANG ?= clang-22
# Kernel types: vmlinux.h is generated from this kernel's BTF (not committed).
# lvh kernel image for Linux 6.12.111; its config is alongside the BTF at
# /data/kernels/6.12/boot/config-6.12.111.
BPF_KERNEL_IMAGE ?= quay.io/lvh-images/kernel-images:6.12-20260928.013030@sha256:26264311dce48e31e0103fcdaaeb1aebfa288db1a27fe3ef3d5619d0ffa628eb
BPF_KERNEL_BTF ?= /data/kernels/6.12/boot/btf-6.12.111

CONTAINER_ENGINE ?= $(if $(shell command -v docker),docker,podman)
VMLINUX_H := attestation/bpf-common/headers/vmlinux.h
BPF_CACHE := .bpf-cache
BPF_RUN = $(CONTAINER_ENGINE) run --rm --platform $(BPF_PLATFORM) \
	--env GOFLAGS=-buildvcs=false \
	--env BPF2GO_CC=$(BPF_CLANG) --env BPF_CFLAGS="$(BPF_CFLAGS)" \
	-v "$(CURDIR)":/src -w /src \
	$(BPF_BUILDER_IMAGE)

.PHONY: vmlinux-h
vmlinux-h: ## Generate vmlinux.h from the pinned kernel's BTF (needs docker or podman)
	@mkdir -p $(BPF_CACHE) $(dir $(VMLINUX_H))
	cid=$$($(CONTAINER_ENGINE) create --platform $(BPF_PLATFORM) $(BPF_KERNEL_IMAGE) /bin/true) && \
		$(CONTAINER_ENGINE) cp $$cid:$(BPF_KERNEL_BTF) $(BPF_CACHE)/vmlinux.btf; rc=$$?; \
		$(CONTAINER_ENGINE) rm $$cid >/dev/null; exit $$rc
	$(BPF_RUN) bpftool btf dump file $(BPF_CACHE)/vmlinux.btf format c > $(VMLINUX_H)

.PHONY: generate-bpf
generate-bpf: vmlinux-h ## Regenerate all BPF objects and Go bindings with the pinned toolchain and kernel (needs docker or podman)
	$(BPF_RUN) go generate ./attestation/commandrun/bpf/... ./attestation/networktrace/bpf/...

.PHONY: generate-bpf-debug
generate-bpf-debug: ## generate with BPF debug logging. Don't commit.
	$(MAKE) generate-bpf BPF_CFLAGS=-DBPF_DEBUG
