# YARA REST Service Makefile
# Cross-platform compatible (Linux, macOS, Windows with make)

# Configuration
BINARY_NAME := yara-rest
DOCKER_IMAGE := yara-rest
DOCKER_TAG := latest

.PHONY: all build test test-verbose test-cover clean fmt vet lint \
        docker-build docker-run docker-stop docker-test help

# Default target
all: fmt vet test build

# Build the binary
build:
	go build -ldflags "-s -w" -o $(BINARY_NAME) .

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with coverage report
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run unit tests only (skip integration tests)
test-unit:
	go test -short ./...

# Run tests with race detector (requires CGO/gcc)
test-race:
	CGO_ENABLED=1 go test -race ./...

# Clean build artifacts
clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Run static analysis (requires golangci-lint)
lint:
	@which golangci-lint > /dev/null || (echo "Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run

# =============================================================================
# Docker targets
# =============================================================================

# Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Build with Podman (for systems without Docker)
podman-build:
	podman build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Run container (mount local test rules)
docker-run:
	docker run -d --name $(BINARY_NAME) \
		-p 9001:9001 \
		-v $(CURDIR)/test:/rules:ro \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# Run with Podman
podman-run:
	podman run -d --name $(BINARY_NAME) \
		-p 9001:9001 \
		-v $(CURDIR)/test:/rules:ro \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# Stop and remove container
docker-stop:
	docker stop $(BINARY_NAME) || true
	docker rm $(BINARY_NAME) || true

# Stop with Podman
podman-stop:
	podman stop $(BINARY_NAME) || true
	podman rm $(BINARY_NAME) || true

# Run integration tests in container
docker-test: docker-build docker-stop docker-run
	@echo "Waiting for container to start..."
	@sleep 3
	@curl -sf http://localhost:9001/health && echo "Health check passed"
	@docker stop $(BINARY_NAME)
	@docker rm $(BINARY_NAME)

# =============================================================================
# Development targets
# =============================================================================

# Run locally (requires YARA-X installed)
run: build
	YARA_RULES_PATH=./test ./$(BINARY_NAME)

# Watch for changes and rebuild (requires entr)
watch:
	@which entr > /dev/null || (echo "Install entr: https://github.com/eradman/entr" && exit 1)
	find . -name '*.go' | entr -r make run

# =============================================================================
# Help
# =============================================================================

help:
	@echo "YARA REST Service - Available targets:"
	@echo ""
	@echo "Build & Test:"
	@echo "  make build        - Build the binary"
	@echo "  make test         - Run all tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make test-cover   - Run tests with coverage report"
	@echo "  make test-unit    - Run unit tests only (skip integration)"
	@echo "  make clean        - Remove build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt          - Format code"
	@echo "  make vet          - Run go vet"
	@echo "  make lint         - Run golangci-lint"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run container"
	@echo "  make docker-stop  - Stop and remove container"
	@echo "  make docker-test  - Build, run, and test container"
	@echo ""
	@echo "Podman (alternative to Docker):"
	@echo "  make podman-build - Build with Podman"
	@echo "  make podman-run   - Run with Podman"
	@echo "  make podman-stop  - Stop with Podman"
	@echo ""
	@echo "Development:"
	@echo "  make run          - Build and run locally"
	@echo "  make watch        - Watch for changes and rebuild"
