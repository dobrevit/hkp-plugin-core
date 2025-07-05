# Makefile for HKP Plugin Project

# Variables
GO := go
GOCMD := $(GO)
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags
BUILD_FLAGS := -buildmode=plugin
APP_BUILD_FLAGS := 

# Directories
PLUGIN_DIR := src/plugins
CMD_DIR := cmd/interpose
OUTPUT_DIR := $(CMD_DIR)/plugins
BINARY_NAME := interpose

# Plugin names
PLUGINS := antiabuse mlabuse ratelimit-geo ratelimit-ml ratelimit-tarpit ratelimit-threat zerotrust

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Default target
.PHONY: all
all: clean deps plugins app
	@echo "$(GREEN)✓ Build complete!$(NC)"

# Dependencies
.PHONY: deps
deps:
	@echo "$(YELLOW)→ Downloading dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) tidy

# Create output directory
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Build all plugins
.PHONY: plugins
plugins: $(OUTPUT_DIR) $(PLUGINS)
	@echo "$(GREEN)✓ All plugins built successfully!$(NC)"

# Individual plugin targets
.PHONY: $(PLUGINS)
$(PLUGINS):
	@echo "$(YELLOW)→ Building plugin: $@$(NC)"
	@cd $(PLUGIN_DIR)/$@ && $(GOBUILD) $(BUILD_FLAGS) -o ../../../$(OUTPUT_DIR)/$@.so .
	@echo "$(GREEN)✓ Plugin $@ built: $(OUTPUT_DIR)/$@.so$(NC)"

# Build the main application
.PHONY: app
app:
	@echo "$(YELLOW)→ Building application: $(BINARY_NAME)$(NC)"
	@cd $(CMD_DIR) && $(GOBUILD) $(APP_BUILD_FLAGS) -o $(BINARY_NAME) .
	@echo "$(GREEN)✓ Application built: $(CMD_DIR)/$(BINARY_NAME)$(NC)"

# Build specific plugin
.PHONY: plugin-%
plugin-%:
	@echo "$(YELLOW)→ Building plugin: $*$(NC)"
	@cd $(PLUGIN_DIR)/$* && $(GOBUILD) $(BUILD_FLAGS) -o ../../../$(OUTPUT_DIR)/$*.so .
	@echo "$(GREEN)✓ Plugin $* built: $(OUTPUT_DIR)/$*.so$(NC)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "$(YELLOW)→ Cleaning build artifacts...$(NC)"
	@rm -rf $(OUTPUT_DIR)/*.so
	@rm -f $(CMD_DIR)/$(BINARY_NAME)
	$(GOCLEAN)
	@echo "$(GREEN)✓ Clean complete!$(NC)"

# Run tests
.PHONY: test
test:
	@echo "$(YELLOW)→ Running tests...$(NC)"
	@./scripts/test-all.sh

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "$(YELLOW)→ Running tests with coverage...$(NC)"
	@./scripts/test-all.sh --coverage

# Run tests in verbose mode
.PHONY: test-verbose
test-verbose:
	@echo "$(YELLOW)→ Running tests (verbose)...$(NC)"
	@./scripts/test-all.sh --verbose

# Run quick unit tests only
.PHONY: test-unit
test-unit:
	@echo "$(YELLOW)→ Running unit tests...$(NC)"
	$(GOTEST) ./pkg/... ./src/...

# Format code
.PHONY: fmt
fmt:
	@echo "$(YELLOW)→ Formatting code...$(NC)"
	$(GOCMD) fmt ./...
	@echo "$(GREEN)✓ Code formatted!$(NC)"

# Run linter
.PHONY: lint
lint:
	@echo "$(YELLOW)→ Running linter...$(NC)"
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "$(RED)✗ golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest$(NC)"; \
	fi

# Install the application
.PHONY: install
install: app
	@echo "$(YELLOW)→ Installing $(BINARY_NAME)...$(NC)"
	@cp $(CMD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "$(GREEN)✓ $(BINARY_NAME) installed to $(GOPATH)/bin/$(NC)"

# Run the application
.PHONY: run
run: plugins app
	@echo "$(YELLOW)→ Running $(BINARY_NAME)...$(NC)"
	@cd $(CMD_DIR) && ./$(BINARY_NAME) -config ./config.toml

# Development mode - build and run
.PHONY: dev
dev: plugins app run

# Help
.PHONY: help
help:
	@echo "$(GREEN)HKP Plugin Project Makefile$(NC)"
	@echo ""
	@echo "Available targets:"
	@echo "  $(YELLOW)all$(NC)             - Clean, download deps, build plugins and app"
	@echo "  $(YELLOW)deps$(NC)            - Download and tidy dependencies"
	@echo "  $(YELLOW)plugins$(NC)         - Build all plugins"
	@echo "  $(YELLOW)app$(NC)             - Build the main application"
	@echo "  $(YELLOW)plugin-<name>$(NC)   - Build a specific plugin (e.g., plugin-antiabuse)"
	@echo "  $(YELLOW)clean$(NC)           - Remove build artifacts"
	@echo "  $(YELLOW)test$(NC)            - Run tests"
	@echo "  $(YELLOW)test-coverage$(NC)   - Run tests with coverage"
	@echo "  $(YELLOW)fmt$(NC)             - Format code"
	@echo "  $(YELLOW)lint$(NC)            - Run linter"
	@echo "  $(YELLOW)install$(NC)         - Install the application to GOPATH/bin"
	@echo "  $(YELLOW)run$(NC)             - Run the application"
	@echo "  $(YELLOW)dev$(NC)             - Development mode (build and run)"
	@echo "  $(YELLOW)help$(NC)            - Show this help message"
	@echo ""
	@echo "Plugins:"
	@for plugin in $(PLUGINS); do \
		echo "  - $$plugin"; \
	done