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
	docker run -v ./:/app -w /app --platform linux/amd64 cgr.dev/chainguard/go run ./schemagen/schema.go

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

lint: ## Run the linter
	@golangci-lint run
	@go fmt ./...
	@go vet ./...

.PHONY: check-aws-certs
check-aws-certs: ## Check the AWS public keys used to verify AWS IID documents
	GOWORK=off go run -C ./attestation/aws-iid/check-certs/ . ../aws-certs.go

# Pinned eBPF toolchain image (clang-22 / llvm-strip-22 / bpftool / Go). Keep this
# digest in sync with .github/workflows/verify-bpf.yml so local and CI builds match.
EBPF_BUILDER_IMAGE ?= ghcr.io/cilium/ebpf-builder:1777990914@sha256:22ce6d5aad2f15df921db21770e759554cbda52f6d4e291b1ff58b4b9a5d6fcb

.PHONY: generate-bpf
generate-bpf: ## Regenerate the networktrace BPF objects reproducibly (same process as CI)
	@echo "Regenerating BPF objects in the pinned ebpf-builder (canonical /src path)..."
	docker run --rm -v "$(CURDIR)":/src -w /src $(EBPF_BUILDER_IMAGE) bash -c '\
		ln -sf /usr/bin/clang-22 /usr/local/bin/clang && \
		ln -sf /usr/bin/llvm-strip-22 /usr/local/bin/llvm-strip && \
		GOTOOLCHAIN=auto go generate ./attestation/networktrace/bpf/...'

.PHONY: verify-bpf
verify-bpf: generate-bpf ## Verify the committed BPF objects match a fresh reproducible build (same check as CI)
	@git diff --exit-code -- attestation/networktrace/bpf || { \
		echo "Committed BPF objects differ from a fresh build. Run 'make generate-bpf' and commit the result."; \
		exit 1; \
	}
	@echo "Committed BPF objects are byte-for-byte reproducible from the committed sources."

.PHONY: generate-bpf-debug
generate-bpf-debug: ## Regenerate the BPF objects with debug logging enabled (-DBPF_DEBUG; do not commit)
	@echo "Regenerating BPF objects with DEBUG logging in the pinned ebpf-builder..."
	docker run --rm -v "$(CURDIR)":/src -w /src $(EBPF_BUILDER_IMAGE) bash -c '\
		ln -sf /usr/bin/clang-22 /usr/local/bin/clang && \
		ln -sf /usr/bin/llvm-strip-22 /usr/local/bin/llvm-strip && \
		BPF_CFLAGS=-DBPF_DEBUG GOTOOLCHAIN=auto go generate ./attestation/networktrace/bpf/...'

.PHONY: generate-vmlinux
generate-vmlinux: ## Re-pin headers/vmlinux.h from THIS host's kernel BTF (advanced; breaks reproducibility unless intentionally re-pinning)
	@echo "WARNING: this overwrites the committed, pinned headers/vmlinux.h with this host's kernel types."
	@echo "Only run this to intentionally re-pin the kernel ABI; afterwards run 'make generate-bpf' and commit both."
	@command -v bpftool >/dev/null 2>&1 || { echo "Error: bpftool is required. Install with: apt install linux-tools-common linux-tools-$$(uname -r)"; exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./attestation/networktrace/bpf/headers/vmlinux.h
