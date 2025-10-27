.PHONY: all build run clean help

# Default target
all: build

# Build the project
build:
	@echo "Building WireDolphin..."
	@if [ "$$(uname -s)" = "Linux" ]; then \
		go build -o wiredolphin; \
	else \
		echo "Not on Linux, cross-compiling for Linux..."; \
		GOOS=linux GOARCH=amd64 go build -o wiredolphin-linux-amd64; \
		echo "Created: wiredolphin-linux-amd64"; \
	fi

# Build with race detector (for development)
build-dev:
	@echo "Building WireDolphin with race detector..."
	@go build -race -o wiredolphin

# Run the monitor (requires sudo)
run: build
	@echo "Starting WireDolphin on tun0 (requires root)..."
	@sudo ./wiredolphin

# Run on specific interface
run-iface: build
	@echo "Starting WireDolphin on $(IFACE) (requires root)..."
	@sudo ./wiredolphin $(IFACE)

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Clean build artifacts and logs
clean:
	@echo "Cleaning build artifacts and logs..."
	@rm -f wiredolphin
	@rm -f camada_internet.csv camada_transporte.csv camada_aplicacao.csv

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run tests (if any)
test:
	@echo "Running tests..."
	@go test -v ./...

# Display help
help:
	@echo "WireDolphin Network Traffic Monitor - Makefile Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make build         - Build the binary"
	@echo "  make run           - Build and run on tun0 (requires sudo)"
	@echo "  make run-iface IFACE=eth0 - Build and run on specific interface"
	@echo "  make deps          - Install/update dependencies"
	@echo "  make clean         - Remove build artifacts and CSV logs"
	@echo "  make fmt           - Format source code"
	@echo "  make test          - Run tests"
	@echo "  make help          - Show this help message"
	@echo ""
	@echo "Note: Running the monitor requires root privileges."

