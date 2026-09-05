# ---------------------------------------------------------------------------
# usage:
#   make                   debug build (default)
#   make BUILD=release     release build
#   make run ARGS="a b"    build and run with arguments
#   make test              build and run all tests
#   make CC=clang          use a different compiler
#   make V=1               show full compiler commands
#   make help              list all targets
# ---------------------------------------------------------------------------

BIN      ?= $(notdir $(CURDIR))
BUILD    ?= debug
STD      ?= c17
SANITIZE ?= 1
V        ?= 0

SRC_DIR   := src
INC_DIR   := include
TEST_DIR  := tests
BUILD_DIR := build
OUT_DIR   := $(BUILD_DIR)/$(BUILD)
OBJ_DIR   := $(OUT_DIR)/obj
TARGET    := $(OUT_DIR)/$(BIN)

# --- flags -----------------------------------------------------------------

WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wdouble-promotion \
            -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes \
            -Wnull-dereference -Wvla

CPPFLAGS += -I$(INC_DIR)
CFLAGS   += -std=$(STD) $(WARNINGS)
DEPFLAGS  = -MMD -MP
LDFLAGS  +=
LDLIBS   +=

ifeq ($(BUILD),debug)
  CFLAGS += -O0 -g3 -fno-omit-frame-pointer
  ifeq ($(SANITIZE),1)
    CFLAGS  += -fsanitize=address,undefined
    LDFLAGS += -fsanitize=address,undefined
  endif
else ifeq ($(BUILD),release)
  CFLAGS += -O2 -DNDEBUG
else
  $(error unknown BUILD '$(BUILD)', expected 'debug' or 'release')
endif

ifeq ($(V),1)
  Q :=
else
  Q := @
endif

# --- sources ---------------------------------------------------------------

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)
HDRS := $(shell find $(SRC_DIR) $(INC_DIR) $(TEST_DIR) -name '*.h')

# every tests/*.c becomes its own binary, linked against all objects except main.o
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(TEST_SRCS:$(TEST_DIR)/%.c=$(OUT_DIR)/$(TEST_DIR)/%)
TEST_DEPS := $(TEST_BINS:=.d)
LIB_OBJS  := $(filter-out %/main.o,$(OBJS))

# --- targets ---------------------------------------------------------------

.DEFAULT_GOAL := all
.PHONY: all release run test clean format format-check lint help

all: $(TARGET) compile_commands.json ## build (default, BUILD=debug)

release: ## shortcut for make BUILD=release
	@$(MAKE) --no-print-directory BUILD=release

run: $(TARGET) ## build and run, pass arguments with ARGS="..."
	@./$(TARGET) $(ARGS)

test: $(TEST_BINS) ## build and run all tests
	@for t in $(TEST_BINS); do echo "  RUN     $$t"; ./$$t || exit 1; done
	@echo "all tests passed"

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	@echo "  LD      $@"
	$(Q)$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(OUT_DIR)/$(TEST_DIR)/%: $(TEST_DIR)/%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -MT $@ -MF $@.d $(LDFLAGS) $< $(LIB_OBJS) $(LDLIBS) -o $@

# generated without external tools so clangd works out of the box
compile_commands.json: $(SRCS) $(TEST_SRCS) Makefile
	@echo "  GEN     $@"
	@{ echo '['; \
	   for f in $(SRCS) $(TEST_SRCS); do \
	     printf '  {"directory": "%s", "file": "%s", "command": "%s -c %s"},\n' \
	       "$(CURDIR)" "$$f" "$(CC) $(CPPFLAGS) $(CFLAGS)" "$$f"; \
	   done | sed '$$ s/,$$//'; \
	   echo ']'; } > $@

clean: ## remove build output
	@echo "  CLEAN"
	$(Q)rm -rf $(BUILD_DIR) compile_commands.json

format: ## format all sources with clang-format
	clang-format -i $(SRCS) $(TEST_SRCS) $(HDRS)

format-check: ## verify formatting (used in ci)
	clang-format --dry-run --Werror $(SRCS) $(TEST_SRCS) $(HDRS)

lint: compile_commands.json ## run clang-tidy
	clang-tidy $(SRCS) $(TEST_SRCS)

help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN { FS = ":.*## " } { printf "  %-14s %s\n", $$1, $$2 }'

-include $(DEPS) $(TEST_DEPS)
