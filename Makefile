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

VMLINUX_H := ./attestation/bpf-common/headers/vmlinux.h

.PHONY: generate-vmlinux
generate-vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "Generating vmlinux.h from kernel BTF..."
	@command -v bpftool >/dev/null 2>&1 || { echo "Error: bpftool is required. Install with: apt install linux-tools-common linux-tools-$(uname -r)"; exit 1; }
	mkdir -p ./attestation/bpf-common/headers && bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./attestation/bpf-common/headers/vmlinux.h

.PHONY: generate-commandrun-bpf
generate-commandrun-bpf: generate-vmlinux ## Generate BPF bytecode and Go bindings for command-run file tracing
	@echo "Generating command-run BPF code (requires clang and llvm)..."
	go generate -tags linux ./attestation/commandrun/bpf/...

.PHONY: generate-networktrace-bpf
generate-networktrace-bpf: generate-vmlinux ## Generate BPF bytecode and Go bindings for network trace attestor
	@echo "Generating BPF code (requires clang and llvm)..."
	go generate ./attestation/networktrace/bpf/...

.PHONY: generate-networktrace-bpf-debug
generate-networktrace-bpf-debug: generate-vmlinux ## Generate networktrace BPF bytecode with debug logging enabled
	@echo "Generating BPF code with DEBUG logging (requires clang and llvm)..."
	BPF_CFLAGS="-DBPF_DEBUG" go generate ./attestation/networktrace/bpf/...
