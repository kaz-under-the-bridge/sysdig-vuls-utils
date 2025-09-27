.PHONY: build clean test lint install help

# Binary name
BINARY_NAME=sysdig-vuls
BUILD_DIR=bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build the binary
build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/sysdig-vuls/main.go

# Build for multiple platforms
build-all:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/sysdig-vuls/main.go
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/sysdig-vuls/main.go
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/sysdig-vuls/main.go
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/sysdig-vuls/main.go

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run linting
lint:
	golangci-lint run

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Install the binary
install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

# Run the application
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Format code
fmt:
	$(GOCMD) fmt ./...

# Show help
help:
	@echo "Available commands:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linting"
	@echo "  deps          - Install/update dependencies"
	@echo "  install       - Install binary to /usr/local/bin"
	@echo "  run           - Build and run the application"
	@echo "  fmt           - Format code"
	@echo "  help          - Show this help"