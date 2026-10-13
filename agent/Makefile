# =============================================================================
# Codé Agent — Makefile
# =============================================================================
#
# This Makefile builds the C99 agent for various platform/architecture
# combinations.  It is invoked by the top-level Makefile with the
# appropriate CC, TARGET_OS, TARGET_ARCH, and OUT variables set.
#
# Targets:
#   make native          — Build for the current host platform
#   make (default)       — Cross-compile with CC/TARGET_OS/TARGET_ARCH/OUT
#   make test            — Build and run all tests
#   make test-tlv        — Build and run TLV codec tests
#   make test-safety     — Build and run safety mechanism tests
#   make lint            — Run cppcheck
#   make clean           — Remove build artifacts
#
# ACADEMIC/EDUCATIONAL USE ONLY.
# =============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CC          ?= gcc
CFLAGS      ?= -std=c99 -Wall -Wextra -Wpedantic -Werror -O2
LDFLAGS     ?=

TARGET_OS   ?= linux
TARGET_ARCH ?= amd64
OUT         ?= build/code_agent

# Include paths
INCLUDE     := -Iinclude

# Build-time defines (injected by top-level Makefile or environment)
CIDR_ALLOWLIST  ?= 10.13.37.0/24
EXPIRY_SECONDS  ?= 2592000
SERVER_HOST     ?= 10.13.37.1
SERVER_PORT     ?= 443
BEACON_INTERVAL ?= 30
BEACON_JITTER   ?= 20

# Calculate build expiry as Unix timestamp (current time + EXPIRY_SECONDS)
BUILD_EXPIRY := $(shell date -d "+$(EXPIRY_SECONDS) seconds" +%s 2>/dev/null || \
                  python3 -c "import time; print(int(time.time()) + $(EXPIRY_SECONDS))" 2>/dev/null || \
                  echo "0")

DEFINES     := -DSERVER_HOST=\"$(SERVER_HOST)\" \
               -DSERVER_PORT=$(SERVER_PORT) \
               -DLAB_CIDR=\"$(CIDR_ALLOWLIST)\" \
               -DBUILD_EXPIRY=$(BUILD_EXPIRY) \
               -DBEACON_INTERVAL=$(BEACON_INTERVAL) \
               -DBEACON_JITTER=$(BEACON_JITTER)

# Object directory
OBJ_DIR     := obj/$(TARGET_OS)-$(TARGET_ARCH)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------

# Core sources (always compiled)
SRCS_CORE   := src/main.c \
               src/tlv.c \
               src/safety.c \
               src/protocol.c \
               src/agent.c \
               src/capabilities.c

# Platform-specific source
ifeq ($(TARGET_OS),windows)
  SRCS_PAL  := src/pal_win32.c
  LDFLAGS   += -lws2_32
else
  SRCS_PAL  := src/pal_linux.c
endif

SRCS        := $(SRCS_CORE) $(SRCS_PAL)
OBJS        := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# ---------------------------------------------------------------------------
# Test sources
# ---------------------------------------------------------------------------

TEST_TLV_SRCS    := tests/test_tlv.c src/tlv.c
TEST_SAFETY_SRCS := tests/test_safety.c src/safety.c src/tlv.c

ifeq ($(TARGET_OS),windows)
  TEST_PAL_SRC := src/pal_win32.c
else
  TEST_PAL_SRC := src/pal_linux.c
endif

TEST_SAFETY_SRCS += $(TEST_PAL_SRC)

TEST_BUILD_DIR   := build/tests

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------

.PHONY: all native test test-tlv test-safety lint clean

# ---------------------------------------------------------------------------
# Default target — cross-compile
# ---------------------------------------------------------------------------

all: $(OUT)

$(OUT): $(OBJS)
	@mkdir -p $(dir $(OUT))
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDE) -o $@ $^ $(LDFLAGS)
	@echo "Built: $@"

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDE) -c -o $@ $<

# ---------------------------------------------------------------------------
# Native build (detect host OS and arch)
# ---------------------------------------------------------------------------

# Select the PAL and output name for the host we are building on. On Windows
# the shell sets OS=Windows_NT; elsewhere assume a POSIX host (Linux/macOS).
ifeq ($(OS),Windows_NT)
  NATIVE_PAL := src/pal_win32.c
  NATIVE_BIN := build/native/code_agent.exe
  NATIVE_LDFLAGS := $(LDFLAGS) -lws2_32
else
  NATIVE_PAL := src/pal_linux.c
  NATIVE_BIN := build/native/code_agent
  NATIVE_LDFLAGS := $(LDFLAGS)
endif

native:
	@echo "==> Building agent (native)..."
	@mkdir -p build/native
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDE) -o $(NATIVE_BIN) $(SRCS_CORE) $(NATIVE_PAL) $(NATIVE_LDFLAGS)
	@echo "Built: $(NATIVE_BIN)"

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test: test-tlv test-safety

test-tlv:
	@echo "==> Building TLV codec tests..."
	@mkdir -p $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) $(DEFINES) -DTESTING $(INCLUDE) \
		-o $(TEST_BUILD_DIR)/test_tlv $(TEST_TLV_SRCS) $(LDFLAGS)
	@echo "==> Running TLV codec tests..."
	$(TEST_BUILD_DIR)/test_tlv

test-safety:
	@echo "==> Building safety mechanism tests..."
	@mkdir -p $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) $(DEFINES) -DTESTING $(INCLUDE) \
		-o $(TEST_BUILD_DIR)/test_safety $(TEST_SAFETY_SRCS) $(LDFLAGS)
	@echo "==> Running safety mechanism tests..."
	$(TEST_BUILD_DIR)/test_safety

# ---------------------------------------------------------------------------
# Linting
# ---------------------------------------------------------------------------

lint:
	@echo "==> Linting C code with cppcheck..."
	cppcheck --enable=all --std=c99 --suppress=missingIncludeSystem \
		$(INCLUDE) src/ include/

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	@echo "==> Cleaning agent build artifacts..."
	rm -rf build/ obj/
	@echo "==> Agent clean complete."
