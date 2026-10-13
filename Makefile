# =============================================================================
# Codé — Top-Level Makefile
# =============================================================================
#
# Orchestrates builds for all components:
#   make server      — Build the Go team server
#   make console     — Build the Go operator console
#   make agent       — Build the agent for the current platform
#   make agent-all   — Cross-compile the agent for all 7 targets
#   make certs       — Generate TLS certificates for the lab
#   make test        — Run all tests (Go + C)
#   make clean       — Remove all build artifacts
#   make all         — Build everything (server + console + agent-all)
#
# =============================================================================

.PHONY: all server console agent agent-all certs test clean \
        agent-linux-i386 agent-linux-amd64 agent-linux-armv7 agent-linux-aarch64 \
        agent-windows-i386 agent-windows-amd64 agent-windows-aarch64 \
        proto lint help

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Build output directory
BUILD_DIR    := build
AGENT_DIR    := agent
SERVER_DIR   := server
CONSOLE_DIR  := console
CERTS_DIR    := certs
PROTO_DIR    := proto

# Go configuration
GO           ?= go
GOFLAGS      ?=

# Agent build-time safety defaults
CIDR_ALLOWLIST   ?= 10.13.37.0/24
EXPIRY_SECONDS   ?= 2592000
SERVER_HOST      ?= 10.13.37.1
SERVER_PORT      ?= 443
BEACON_INTERVAL  ?= 30
BEACON_JITTER    ?= 20

# Export for sub-makefiles
export CIDR_ALLOWLIST EXPIRY_SECONDS SERVER_HOST SERVER_PORT
export BEACON_INTERVAL BEACON_JITTER BUILD_DIR

# Cross-compilation toolchains (musl for static Linux, MinGW for Windows)
CC_LINUX_I386      ?= i686-linux-musl-gcc
CC_LINUX_AMD64     ?= x86_64-linux-musl-gcc
CC_LINUX_ARMV7     ?= arm-linux-musleabihf-gcc
CC_LINUX_AARCH64   ?= aarch64-linux-musl-gcc
CC_WINDOWS_I386    ?= i686-w64-mingw32-gcc
CC_WINDOWS_AMD64   ?= x86_64-w64-mingw32-gcc
CC_WINDOWS_AARCH64 ?= aarch64-w64-mingw32-gcc

# Agent binary names
AGENT_BIN_LINUX   := code_agent
AGENT_BIN_WINDOWS := code_agent.exe

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------

all: server console agent-all

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help:
	@echo ""
	@echo "Codé Build System"
	@echo "=========================="
	@echo ""
	@echo "Targets:"
	@echo "  make server           Build the Go team server"
	@echo "  make console          Build the Go operator console"
	@echo "  make agent            Build agent for current platform"
	@echo "  make agent-all        Cross-compile agent for all 7 targets"
	@echo "  make agent-linux-amd64   Build agent for Linux/amd64 (etc.)"
	@echo "  make certs            Generate TLS certificates"
	@echo "  make proto            Regenerate gRPC protobuf code"
	@echo "  make test             Run all tests"
	@echo "  make lint             Run linters"
	@echo "  make clean            Remove build artifacts"
	@echo ""
	@echo "Agent build options:"
	@echo "  CIDR_ALLOWLIST=...    Allowed CIDR ranges (default: 10.13.37.0/24)"
	@echo "  EXPIRY_SECONDS=...   Build expiry in seconds (default: 2592000 / 30d)"
	@echo "  SERVER_HOST=...      Team Server IP (default: 10.13.37.1)"
	@echo "  SERVER_PORT=...      Team Server port (default: 443)"
	@echo "  BEACON_INTERVAL=...  Beacon interval secs (default: 30)"
	@echo "  BEACON_JITTER=...    Jitter percentage (default: 20)"
	@echo ""

# ---------------------------------------------------------------------------
# Team Server (Go)
# ---------------------------------------------------------------------------

server:
	@echo "==> Building Team Server..."
	@mkdir -p $(BUILD_DIR)/server
	cd $(SERVER_DIR) && $(GO) build $(GOFLAGS) -o ../$(BUILD_DIR)/server/serverd ./cmd/serverd

# ---------------------------------------------------------------------------
# Operator Console (Go)
# ---------------------------------------------------------------------------

console:
	@echo "==> Building Operator Console..."
	@mkdir -p $(BUILD_DIR)/console
	cd $(CONSOLE_DIR) && $(GO) build $(GOFLAGS) -o ../$(BUILD_DIR)/console/console ./cmd/console

# ---------------------------------------------------------------------------
# Protobuf / gRPC code generation
# ---------------------------------------------------------------------------

proto:
	@echo "==> Generating protobuf/gRPC code..."
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=$(PROTO_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/c2.proto

# ---------------------------------------------------------------------------
# Agent — native build (current platform)
# ---------------------------------------------------------------------------

agent:
	@echo "==> Building Agent (native)..."
	$(MAKE) -C $(AGENT_DIR) native

# ---------------------------------------------------------------------------
# Agent — cross-compilation for all 7 targets
# ---------------------------------------------------------------------------

agent-all: agent-linux-i386 agent-linux-amd64 agent-linux-armv7 agent-linux-aarch64 \
           agent-windows-i386 agent-windows-amd64 agent-windows-aarch64

agent-linux-i386:
	@echo "==> Building Agent: linux/i386..."
	@mkdir -p $(BUILD_DIR)/agent/linux-i386
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_LINUX_I386) \
		TARGET_OS=linux TARGET_ARCH=i386 \
		OUT=../$(BUILD_DIR)/agent/linux-i386/$(AGENT_BIN_LINUX)

agent-linux-amd64:
	@echo "==> Building Agent: linux/amd64..."
	@mkdir -p $(BUILD_DIR)/agent/linux-amd64
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_LINUX_AMD64) \
		TARGET_OS=linux TARGET_ARCH=amd64 \
		OUT=../$(BUILD_DIR)/agent/linux-amd64/$(AGENT_BIN_LINUX)

agent-linux-armv7:
	@echo "==> Building Agent: linux/armv7..."
	@mkdir -p $(BUILD_DIR)/agent/linux-armv7
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_LINUX_ARMV7) \
		TARGET_OS=linux TARGET_ARCH=armv7 \
		OUT=../$(BUILD_DIR)/agent/linux-armv7/$(AGENT_BIN_LINUX)

agent-linux-aarch64:
	@echo "==> Building Agent: linux/aarch64..."
	@mkdir -p $(BUILD_DIR)/agent/linux-aarch64
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_LINUX_AARCH64) \
		TARGET_OS=linux TARGET_ARCH=aarch64 \
		OUT=../$(BUILD_DIR)/agent/linux-aarch64/$(AGENT_BIN_LINUX)

agent-windows-i386:
	@echo "==> Building Agent: windows/i386..."
	@mkdir -p $(BUILD_DIR)/agent/windows-i386
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_WINDOWS_I386) \
		TARGET_OS=windows TARGET_ARCH=i386 \
		OUT=../$(BUILD_DIR)/agent/windows-i386/$(AGENT_BIN_WINDOWS)

agent-windows-amd64:
	@echo "==> Building Agent: windows/amd64..."
	@mkdir -p $(BUILD_DIR)/agent/windows-amd64
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_WINDOWS_AMD64) \
		TARGET_OS=windows TARGET_ARCH=amd64 \
		OUT=../$(BUILD_DIR)/agent/windows-amd64/$(AGENT_BIN_WINDOWS)

agent-windows-aarch64:
	@echo "==> Building Agent: windows/aarch64..."
	@mkdir -p $(BUILD_DIR)/agent/windows-aarch64
	$(MAKE) -C $(AGENT_DIR) \
		CC=$(CC_WINDOWS_AARCH64) \
		TARGET_OS=windows TARGET_ARCH=aarch64 \
		OUT=../$(BUILD_DIR)/agent/windows-aarch64/$(AGENT_BIN_WINDOWS)

# ---------------------------------------------------------------------------
# TLS Certificate Generation
# ---------------------------------------------------------------------------

certs:
	@echo "==> Generating TLS certificates..."
	chmod +x $(CERTS_DIR)/generate_certs.sh
	cd $(CERTS_DIR) && ./generate_certs.sh

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test: test-server test-console test-agent

test-server:
	@echo "==> Running Team Server tests..."
	cd $(SERVER_DIR) && $(GO) test ./... -v -count=1

test-console:
	@echo "==> Running Operator Console tests..."
	cd $(CONSOLE_DIR) && $(GO) test ./... -v -count=1

test-agent:
	@echo "==> Running Agent tests..."
	$(MAKE) -C $(AGENT_DIR) test

# ---------------------------------------------------------------------------
# Linting
# ---------------------------------------------------------------------------

lint: lint-go lint-c

lint-go:
	@echo "==> Linting Go code..."
	cd $(SERVER_DIR) && golangci-lint run ./...
	cd $(CONSOLE_DIR) && golangci-lint run ./...

lint-c:
	@echo "==> Linting C code..."
	$(MAKE) -C $(AGENT_DIR) lint

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(AGENT_DIR) clean
	cd $(SERVER_DIR) && $(GO) clean
	cd $(CONSOLE_DIR) && $(GO) clean
	@echo "==> Clean complete."
