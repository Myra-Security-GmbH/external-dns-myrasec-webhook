.PHONY: build run test test-coverage test-unit test-integration lint clean dev-deps docker-build

# Build variables
BINARY_NAME=external-dns-myrasec-webhook
GO=go
GOFLAGS=-ldflags="-s -w"

# Test variables
COVER_PROFILE=coverage.out
COVER_HTML=coverage.html

# Docker variables
DOCKER_IMAGE=external-dns-myrasec-webhook
DOCKER_TAG=dev

build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) cmd/webhook/main.go

run: build
	./$(BINARY_NAME)

# Test targets
test-unit:
	$(GO) test -v -short ./...

test-integration:
	$(GO) test -v -run 'Integration' ./...

test: test-unit test-integration

test-coverage:
	$(GO) test -v -coverprofile=$(COVER_PROFILE) ./...
	$(GO) tool cover -html=$(COVER_PROFILE) -o $(COVER_HTML)
	@echo "Coverage report generated at $(COVER_HTML)"
	@go tool cover -func=$(COVER_PROFILE) | grep total:

# Lint targets
lint:
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint is not installed. Please install it to run linting."; \
		exit 1; \
	fi

# Clean targets
clean:
	rm -f $(BINARY_NAME)
	rm -f $(COVER_PROFILE)
	rm -f $(COVER_HTML)
	go clean -cache

# Development helper targets
dev-deps:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/stretchr/testify@latest

docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.DEFAULT_GOAL := build
