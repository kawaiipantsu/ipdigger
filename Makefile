# Makefile for C++ project with security hardening and Debian packaging
# Project configuration
PROJECT_NAME    := ipdigger
VERSION         := 2.2.0
PREFIX          := /usr/local
BINDIR          := $(PREFIX)/bin
MANDIR          := $(PREFIX)/share/man/man1

# Compiler and flags
CXX             := g++
CXXFLAGS        := -std=c++17 -Wall -Wextra -Wpedantic -Werror
CXXFLAGS        += -O2 -g

# Security hardening flags
CXXFLAGS        += -D_FORTIFY_SOURCE=2
CXXFLAGS        += -fstack-protector-strong
CXXFLAGS        += -fPIE
CXXFLAGS        += -Wformat -Wformat-security
CXXFLAGS        += -fno-strict-overflow
CXXFLAGS        += -fstack-clash-protection
CXXFLAGS        += -fcf-protection

LDFLAGS         := -pie -Wl,-z,relro,-z,now,-z,noexecstack
LDFLAGS         += -Wl,--as-needed
LDFLAGS         += -lcurl -lssl -lcrypto -lmaxminddb -lz -lbz2 -llzma

# Directories
SRCDIR          := src
INCDIR          := include
OBJDIR          := obj
BINDIR_LOCAL    := bin
TESTDIR         := tests
DEBDIR          := debian
THIRDPARTYDIR   := third_party

# Source files
SOURCES         := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS         := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
DEPENDS         := $(OBJECTS:.o=.d)
TARGET          := $(BINDIR_LOCAL)/$(PROJECT_NAME)

# Test files
TEST_SOURCES    := $(wildcard $(TESTDIR)/*.cpp)
TEST_OBJECTS    := $(TEST_SOURCES:$(TESTDIR)/%.cpp=$(OBJDIR)/test_%.o)
TEST_TARGET     := $(BINDIR_LOCAL)/test_$(PROJECT_NAME)

# Debian package
DEB_PACKAGE     := $(PROJECT_NAME)_$(VERSION)_amd64.deb
INSTALL_ROOT    := $(DEBDIR)/$(PROJECT_NAME)

# Colors for output
RESET           := \033[0m
BOLD            := \033[1m
RED             := \033[31m
GREEN           := \033[32m
YELLOW          := \033[33m
BLUE            := \033[34m

# Default target
.DEFAULT_GOAL := all

# Phony targets
.PHONY: all clean clean-all build test install uninstall deb help dirs third-party

# Help target
help:
	@echo "$(BOLD)Available targets:$(RESET)"
	@echo "  $(GREEN)make$(RESET) or $(GREEN)make all$(RESET)     - Build the project"
	@echo "  $(GREEN)make build$(RESET)            - Build the project (same as all)"
	@echo "  $(GREEN)make test$(RESET)             - Build and run tests"
	@echo "  $(GREEN)make install$(RESET)          - Install to $(PREFIX)"
	@echo "  $(GREEN)make uninstall$(RESET)        - Remove installed files"
	@echo "  $(GREEN)make deb$(RESET)              - Create Debian package"
	@echo "  $(GREEN)make clean$(RESET)            - Remove build artifacts"
	@echo "  $(GREEN)make help$(RESET)             - Show this help message"
	@echo ""
	@echo "$(BOLD)Configuration:$(RESET)"
	@echo "  Project: $(PROJECT_NAME) v$(VERSION)"
	@echo "  Compiler: $(CXX)"
	@echo "  Install prefix: $(PREFIX)"

# Create necessary directories
dirs:
	@mkdir -p $(OBJDIR) $(BINDIR_LOCAL)

# Download third-party dependencies
third-party: dirs
	@echo "$(YELLOW)Downloading nlohmann/json header...$(RESET)"
	@mkdir -p $(THIRDPARTYDIR)
	@if [ ! -f $(THIRDPARTYDIR)/json.hpp ]; then \
		curl -L -o $(THIRDPARTYDIR)/json.hpp \
			https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp && \
		echo "$(GREEN)✓ Downloaded json.hpp$(RESET)"; \
	else \
		echo "$(GREEN)✓ json.hpp already exists$(RESET)"; \
	fi

# Build all
all: third-party $(TARGET)
	@echo "$(GREEN)✓ Build complete: $(TARGET)$(RESET)"

build: all

# Link target
$(TARGET): $(OBJECTS)
	@echo "$(BLUE)Linking $(notdir $@)...$(RESET)"
	@$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | dirs
	@echo "$(BLUE)Compiling $(notdir $<)...$(RESET)"
	@$(CXX) $(CXXFLAGS) -I$(INCDIR) -I$(THIRDPARTYDIR) -MMD -MP -c $< -o $@

# Include dependencies
-include $(DEPENDS)

# Test target
test: dirs $(TEST_TARGET)
	@echo "$(YELLOW)Running tests...$(RESET)"
	@./$(TEST_TARGET)
	@echo "$(GREEN)✓ All tests passed$(RESET)"

# Build test executable
$(TEST_TARGET): $(TEST_OBJECTS) $(filter-out $(OBJDIR)/main.o, $(OBJECTS))
	@echo "$(BLUE)Linking test executable...$(RESET)"
	@$(CXX) $^ -o $@ $(LDFLAGS)

# Compile test files
$(OBJDIR)/test_%.o: $(TESTDIR)/%.cpp | dirs
	@echo "$(BLUE)Compiling test $(notdir $<)...$(RESET)"
	@$(CXX) $(CXXFLAGS) -I$(INCDIR) -I$(SRCDIR) -I$(THIRDPARTYDIR) -MMD -MP -c $< -o $@

# Install target
install: $(TARGET)
	@echo "$(YELLOW)Installing $(PROJECT_NAME)...$(RESET)"
	@install -d $(DESTDIR)$(BINDIR)
	@install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(PROJECT_NAME)
	@if [ -f $(PROJECT_NAME).1 ]; then \
		echo "$(YELLOW)Installing man page...$(RESET)"; \
		install -d $(DESTDIR)$(MANDIR); \
		gzip -c $(PROJECT_NAME).1 > $(DESTDIR)$(MANDIR)/$(PROJECT_NAME).1.gz; \
		echo "$(GREEN)✓ Installed man page to $(DESTDIR)$(MANDIR)/$(PROJECT_NAME).1.gz$(RESET)"; \
	fi
	@echo "$(GREEN)✓ Installed to $(DESTDIR)$(BINDIR)/$(PROJECT_NAME)$(RESET)"

# Uninstall target
uninstall:
	@echo "$(YELLOW)Uninstalling $(PROJECT_NAME)...$(RESET)"
	@rm -f $(DESTDIR)$(BINDIR)/$(PROJECT_NAME)
	@rm -f $(DESTDIR)$(MANDIR)/$(PROJECT_NAME).1.gz
	@echo "$(GREEN)✓ Uninstalled$(RESET)"

# Create Debian package
deb: all
	@echo "$(YELLOW)Creating Debian package...$(RESET)"
	@rm -rf $(DEBDIR)
	@mkdir -p $(INSTALL_ROOT)$(BINDIR)
	@mkdir -p $(INSTALL_ROOT)$(MANDIR)
	@mkdir -p $(INSTALL_ROOT)/DEBIAN
	@install -m 755 $(TARGET) $(INSTALL_ROOT)$(BINDIR)/$(PROJECT_NAME)
	@if [ -f $(PROJECT_NAME).1 ]; then \
		gzip -c $(PROJECT_NAME).1 > $(INSTALL_ROOT)$(MANDIR)/$(PROJECT_NAME).1.gz; \
	fi
	@echo "Package: $(PROJECT_NAME)" > $(INSTALL_ROOT)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo "Section: utils" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo "Priority: optional" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo "Architecture: amd64" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo "Maintainer: Kawaiipantsu <thugsred@protonmail.com>" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo "Homepage: https://github.com/kawaiipantsu/ipdigger" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo "Description: $(PROJECT_NAME) - IP address analysis tool" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo " A secure C++ tool for extracting and enriching IP addresses from log files." >> $(INSTALL_ROOT)/DEBIAN/control
	@echo " Supports GeoIP, reverse DNS, WHOIS, AbuseIPDB, TLS/SSL inspection," >> $(INSTALL_ROOT)/DEBIAN/control
	@echo " HTTP detection, login tracking, time-range filtering, and multi-threaded" >> $(INSTALL_ROOT)/DEBIAN/control
	@echo " parsing for high-performance analysis of large log files." >> $(INSTALL_ROOT)/DEBIAN/control
	@dpkg-deb --build $(INSTALL_ROOT) $(DEB_PACKAGE)
	@echo "$(GREEN)✓ Created $(DEB_PACKAGE)$(RESET)"

# Clean target
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(RESET)"
	@rm -rf $(OBJDIR) $(BINDIR_LOCAL) $(DEBDIR) *.deb
	@# Note: Not cleaning third_party/ to avoid re-downloading
	@echo "$(GREEN)✓ Clean complete$(RESET)"

# Clean everything including third-party dependencies
clean-all: clean
	@echo "$(YELLOW)Cleaning third-party libraries...$(RESET)"
	@rm -rf $(THIRDPARTYDIR)
	@echo "$(GREEN)✓ Clean all complete$(RESET)"

# Debug info
debug:
	@echo "$(BOLD)Build Configuration:$(RESET)"
	@echo "SOURCES: $(SOURCES)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "CXXFLAGS: $(CXXFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
