
# removes static build artifacts
.PHONY: clean
clean:
	@echo "--------------> Running 'make clean'"
	@rm -rf binaries tmp
	rm -f *.tgz

# Define the `build` target
GATEWAY ?= gateway

.PHONY: build
build:
	go build -o  binaries/$(GATEWAY) .

docker: build
	cp binaries/$(GATEWAY) . && docker build -t gateway

.PHONY: test
test:
	USE_TESTCONTAINERS=1 gotestsum --rerun-fails --format github-actions --packages="./..." -- -timeout=30m


# Define variables for the suite group, path, and name with defaults
SUITE_GROUP ?= 'connectors'
SUITE_PATH ?= 'postgres'
SUITE_NAME ?= 'postgres'
SHELL := /bin/bash

# Define the `run-tests` target
.PHONY: run-tests
run-tests:
	@echo "Running $(SUITE_GROUP) suite $(SUITE_NAME)"
	for dir in $$(find ./$(SUITE_GROUP)/$(SUITE_PATH) -type d); do \
	  if ls "$$dir"/*_test.go >/dev/null 2>&1; then \
	    echo "::group::$$dir"; \
	    echo "Running tests for directory: $$dir"; \
	    sanitized_dir=$$(echo "$$dir" | sed 's|/|_|g'); \
	    gotestsum \
	      --junitfile="reports/$(SUITE_NAME)_$$sanitized_dir.xml" \
	      --junitfile-project-name="$(SUITE_GROUP)" \
	      --junitfile-testsuite-name="short" \
	      --rerun-fails \
	      --format github-actions \
	      --packages="$$dir" \
	      -- -timeout=15m; \
	    echo "::endgroup::"; \
	  else \
	    echo "No Go test files found in $$dir, skipping tests."; \
	  fi \
	done

# Login to GitHub Container Registry
.PHONY: login-ghcr
login-ghcr:
	echo "${GHCR_TOKEN}" | docker login ghcr.io -u ${GITHUB_USERNAME} --password-stdin

# Package the Helm chart
.PHONY: helm-package
helm-package:
	helm package $(HELM_CHART_PATH) --destination .

# Push the Helm chart as OCI artifact
.PHONY: helm-push
helm-push: helm-package login-ghcr
	helm push ./gateway-$(VERSION).tgz oci://$(IMAGE_NAME)
