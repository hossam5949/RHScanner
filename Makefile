# ──────────────────────────────────────────────────────────────────────────────
#  RH Scanner — Makefile (CMake wrapper)
#
#  Usage:
#    make            Build release binary  (default)
#    make debug      Build with ASAN/UBSAN + debug symbols
#    make clean      Remove build artifacts
#    make install    Install to /usr/local/bin  (may need sudo)
#    make run        Build and run with --help
# ──────────────────────────────────────────────────────────────────────────────

BUILD_DIR_RELEASE := build/release
BUILD_DIR_DEBUG   := build/debug
BINARY            := rhscanner
CMAKE             := cmake
NPROC             := $(shell nproc 2>/dev/null || echo 4)

.PHONY: all release debug clean install run help

# Default target
all: release

# ── Release build ──────────────────────────────────────────────────────────────
release:
	@mkdir -p $(BUILD_DIR_RELEASE)
	@$(CMAKE) -S . -B $(BUILD_DIR_RELEASE) \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-Wno-dev \
		--log-level=WARNING
	@$(CMAKE) --build $(BUILD_DIR_RELEASE) --parallel $(NPROC)
	@cp $(BUILD_DIR_RELEASE)/$(BINARY) .
	@echo ""
	@echo "  Built: ./$(BINARY)  (release)"

# ── Debug build ────────────────────────────────────────────────────────────────
debug:
	@mkdir -p $(BUILD_DIR_DEBUG)
	@$(CMAKE) -S . -B $(BUILD_DIR_DEBUG) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-Wno-dev \
		--log-level=WARNING
	@$(CMAKE) --build $(BUILD_DIR_DEBUG) --parallel $(NPROC)
	@cp $(BUILD_DIR_DEBUG)/$(BINARY) .
	@echo ""
	@echo "  Built: ./$(BINARY)  (debug + ASAN)"

# ── Clean ──────────────────────────────────────────────────────────────────────
clean:
	@rm -rf build $(BINARY)
	@echo "  Cleaned build artifacts."

# ── Install ────────────────────────────────────────────────────────────────────
install: release
	@$(CMAKE) --install $(BUILD_DIR_RELEASE) --prefix /usr/local
	@echo "  Installed to /usr/local/bin/$(BINARY)"

# ── Quick run ─────────────────────────────────────────────────────────────────
run: release
	@./$(BINARY) --help

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo "Targets:"
	@echo "  make          Build release binary (default)"
	@echo "  make debug    Build with debug symbols + ASAN/UBSAN"
	@echo "  make clean    Remove build/ and binary"
	@echo "  make install  Install to /usr/local/bin"
	@echo "  make run      Build and run --help"
