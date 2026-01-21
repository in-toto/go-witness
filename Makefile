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

benchmark: ## Run benchmarks with profiling and save results
	go test -v -bench=. -benchmem -benchtime=10s \
		-cpuprofile=cpu.prof -memprofile=mem.prof \
		./attestation/file/ | tee benchmark.txt

benchmark-stat: install-benchstat ## Run benchmarks 10 times for statistical analysis
	go test -bench=. -benchmem -benchtime=10s -count=10 \
		./attestation/file/ | tee benchmark_runs.txt
	@echo "\n=== Statistical Summary ==="
	$(shell go env GOPATH)/bin/benchstat benchmark_runs.txt

benchmark-compare: install-benchstat ## Compare current benchmark with baseline
	@if [ ! -f benchmark_baseline.txt ]; then \
		echo "No baseline found. Run 'make benchmark-baseline' first"; \
		exit 1; \
	fi
	@echo "Running new benchmark..."
	@go test -bench=. -benchmem -benchtime=10s -count=10 \
		./attestation/file/ > benchmark_new.txt
	@echo "\n=== Comparison: Baseline vs New ==="
	$(shell go env GOPATH)/bin/benchstat benchmark_baseline.txt benchmark_new.txt

.PHONY: install-benchstat
install-benchstat: ## Install benchstat if not present
	@which benchstat >/dev/null 2>&1 || \
		(echo "Installing benchstat..." && go install golang.org/x/perf/cmd/benchstat@latest)

benchmark-baseline: ## Save current benchmark as baseline
	@echo "Running baseline benchmark..."
	@go test -bench=. -benchmem -benchtime=10s -count=10 \
		./attestation/file/ > benchmark_baseline.txt
	@echo "Baseline saved to benchmark_baseline.txt"

view-cpu: ## View CPU profile in browser
	go tool pprof -http=:6060 cpu.prof

view-mem: ## View memory profile in browser
	go tool pprof -http=:6060 mem.prof