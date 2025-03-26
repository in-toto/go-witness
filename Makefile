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

.PHONY: schema
schema: ## Generate the attestor schema json files
	go run ./schemagen/schema.go

WITNESS_TMP_DIR := /tmp/witness-build-test
CURRENT_SHA := $(shell git rev-parse HEAD)
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GO_WITNESS_MODULE := github.com/in-toto/go-witness
GO_WITNESS_PATH ?= $(shell pwd)

.PHONY: build-witness
build-witness: ## Build the witness CLI using local go-witness code (or SHA in CI)
	# Usage: make build-witness GO_WITNESS_PATH=/path/to/go-witness (defaults to current dir)
	@echo "Using go-witness SHA: $(CURRENT_SHA)"
	@echo "Current branch: $(CURRENT_BRANCH)"
	
	# Create clean temporary directory
	rm -rf $(WITNESS_TMP_DIR)
	mkdir -p $(WITNESS_TMP_DIR)
	
	# Clone witness repository
	git clone https://github.com/in-toto/witness.git $(WITNESS_TMP_DIR)
	
	# Update go-witness dependency to use local code
	cd $(WITNESS_TMP_DIR) && \
		go mod edit -replace $(GO_WITNESS_MODULE)=$(GO_WITNESS_PATH) && \
		go mod tidy
	
	# Build witness
	cd $(WITNESS_TMP_DIR) && \
		go build -o witness .
	
	@echo "Witness successfully built with go-witness SHA: $(CURRENT_SHA)"
	@echo "Binary located at: $(WITNESS_TMP_DIR)/witness"
	
	# Verify the binary works
	$(WITNESS_TMP_DIR)/witness version

.PHONY: clean-witness
clean-witness: ## Clean up witness build environment
	rm -rf $(WITNESS_TMP_DIR)

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

lint: ## Run the linter
	@golangci-lint run
	@go fmt ./...
	@go vet ./...
