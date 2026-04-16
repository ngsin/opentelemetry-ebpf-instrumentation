# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# OBI C++ Agent - Build system
#

CC      ?= gcc
CFLAGS  := -Wall -Wextra -Werror -O2 -fPIC -fvisibility=hidden -std=c11
LDFLAGS := -shared -nostartfiles -Wl,--no-undefined
LDLIBS  := -ldl

SRC_DIR := src
TEST_DIR := test
BUILD_DIR := build
EMBEDDED_DIR := embedded

AGENT_SO := $(EMBEDDED_DIR)/obi-cpp-agent.so

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Test source files
TEST_SRCS := $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))

.PHONY: all clean test

all: $(AGENT_SO)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(EMBEDDED_DIR):
	mkdir -p $(EMBEDDED_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(AGENT_SO): $(OBJS) | $(EMBEDDED_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Tests
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		$$t || exit 1; \
	done
	@echo "All tests passed."

# Objects that reference symbols only defined in agent.o (e.g. g_obi_config, g_traces_ctx_fd)
AGENT_ONLY_OBJS := $(BUILD_DIR)/agent.o $(BUILD_DIR)/http_server_hooks.o $(BUILD_DIR)/hooks.o $(BUILD_DIR)/curl_hooks.o

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(filter-out $(AGENT_ONLY_OBJS),$(OBJS)) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< $(filter %.o,$^) -ldl

clean:
	rm -rf $(BUILD_DIR) $(AGENT_SO)

# Show build info
info:
	@echo "Sources: $(SRCS)"
	@echo "Objects: $(OBJS)"
	@echo "Tests:   $(TEST_SRCS)"
	@echo "Output:  $(AGENT_SO)"
