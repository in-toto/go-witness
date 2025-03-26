# Makefile to build witness CLI using current go-witness PR SHA
.PHONY: build-witness clean

WITNESS_TMP_DIR := /tmp/witness-build-test
CURRENT_SHA := $(shell git rev-parse HEAD)
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GO_WITNESS_MODULE := github.com/in-toto/go-witness

build-witness:
	@echo "Using go-witness SHA: $(CURRENT_SHA)"
	@echo "Current branch: $(CURRENT_BRANCH)"
	
	# Create clean temporary directory
	rm -rf $(WITNESS_TMP_DIR)
	mkdir -p $(WITNESS_TMP_DIR)
	
	# Clone witness repository
	git clone https://github.com/in-toto/witness.git $(WITNESS_TMP_DIR)
	
	# Update go-witness dependency to use our current SHA
	cd $(WITNESS_TMP_DIR) && \
	go get $(GO_WITNESS_MODULE)@$(CURRENT_SHA) && \
	go mod tidy
	
	# Build witness
	cd $(WITNESS_TMP_DIR) && \
	go build -o witness .
	
	@echo "Witness successfully built with go-witness SHA: $(CURRENT_SHA)"
	@echo "Binary located at: $(WITNESS_TMP_DIR)/witness"
	
	# Verify the binary works
	$(WITNESS_TMP_DIR)/witness version

clean:
	rm -rf $(WITNESS_TMP_DIR)