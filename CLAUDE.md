# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

IPDigger is a log analysis tool that extracts IP addresses and timestamps from text files and displays them in ASCII tables or JSON format. It supports glob patterns for processing multiple files, detailed line-by-line output, and statistical aggregation modes.

## Build Commands

### Basic Operations
```bash
make              # Build the project
make test         # Build and run test suite
make clean        # Remove all build artifacts
make help         # Display all available targets
```

### Installation & Packaging
```bash
make install      # Install to /usr/local/bin (requires sudo)
make uninstall    # Remove installed binaries
make deb          # Create Debian package (ipdigger_1.0.0_amd64.deb)
```

### Testing the Tool
```bash
# Build and test with sample log
make
./bin/ipdigger sample.log                      # Show table of all IPs with dates
./bin/ipdigger --stats sample.log              # Show statistics per IP
./bin/ipdigger --output-json sample.log        # JSON output
./bin/ipdigger --stats --output-json sample.log # JSON stats output

# Test with real logs
./bin/ipdigger /var/log/nginx/access.log
./bin/ipdigger --stats /var/log/auth.log
./bin/ipdigger --output-json /var/log/auth.log

# Test with multiple files (glob patterns)
./bin/ipdigger "/var/log/*.log"                # Quote to prevent shell expansion
./bin/ipdigger --stats "/var/log/nginx/*.log"
./bin/ipdigger --output-json "test*.log"
```

## Architecture

### Core Components

**src/ipdigger.cpp**: Core functionality
- `extract_ip_addresses()`: Regex-based extraction of IPv4 and IPv6 addresses
- `extract_date()`: Multi-format date parsing (ISO8601, Apache, Syslog, etc.)
- `parse_file()`: Line-by-line file parsing and IP/date extraction (adds filename to entries)
- `parse_files()`: Parse multiple files with error handling (continues on file errors)
- `expand_glob()`: POSIX glob pattern expansion for wildcards (*, ?, [...])
- `generate_statistics()`: Aggregate IPs with first/last seen and count
- `print_table()`: ASCII table output showing unique IPs (shows filename column if multiple files)
- `print_stats_table()`: ASCII table output for statistics view
- `print_json()`: JSON output for unique IPs (includes filename field if multiple files)
- `print_stats_json()`: JSON output for statistics
- `json_escape()`: Helper function for secure JSON string escaping

**src/main.cpp**: CLI interface
- Command-line argument parsing
- Glob pattern expansion for file paths
- `--stats` mode switching
- `--output-json` flag handling
- Error handling and user feedback
- Multi-file processing coordination

**include/ipdigger.h**: Public API
- `IPEntry`: Single IP occurrence with line number, timestamp, and filename
- `IPStats`: Aggregated statistics per unique IP
- Glob expansion and multi-file parsing functions

### Date Format Support

The tool detects and parses multiple timestamp formats automatically:
1. Common format: `2024-01-13 12:34:56`
2. ISO 8601/RFC3339: `2024-01-13T12:34:56Z`
3. Apache/Nginx logs: `[13/Jan/2024:12:34:56 +0000]`
4. Syslog format: `Jan 13 12:34:56`
5. Date only: `2024-01-13`

Patterns are tried in order; first match wins per line.

### IP Address Detection

Uses regex patterns for:
- **IPv4**: Standard dotted decimal (0.0.0.0 to 255.255.255.255)
- **IPv6**: Multiple formats including compressed notation and IPv4-mapped addresses

### Output Modes

**Normal Mode**: Displays unique IP addresses only (first occurrence per IP)
- Uses `std::set` to track seen IPs
- Shows line number where IP first appeared
- Shows timestamp from first occurrence
- Line numbers may not be sequential (due to filtering duplicates)
- Available in ASCII table or JSON format

**Statistics Mode**: Displays aggregated data per unique IP
- Shows count of total occurrences
- Shows first and last seen timestamps
- Sorted by count (descending)
- Available in ASCII table or JSON format

**JSON Output**: Secure JSON formatting
- Proper escaping of special characters (quotes, backslashes, control characters)
- Timestamps provided as Unix epoch (seconds since 1970-01-01)
- Null values for missing dates
- Valid JSON structure for easy parsing
- Can be combined with `--stats` flag
- Includes `filename` field when processing multiple files

**Glob Pattern Support**: Multiple file processing
- Uses POSIX `glob()` function for pattern expansion
- Supports wildcards: `*` (any chars), `?` (single char), `[...]` (character set)
- Automatically filters to regular files only (skips directories)
- Gracefully handles files that can't be read (logs warning, continues with others)
- Shows filename column in table output only when >1 file processed
- Shell should NOT expand patterns - quote them: `"*.log"` not `*.log`

### Security-First Compilation

All security hardening flags are mandatory and must not be removed:

**Memory Protection:**
- `-D_FORTIFY_SOURCE=2`: Buffer overflow detection in libc functions
- `-fPIE` + `-pie`: Position-independent executable for ASLR
- `-fstack-protector-strong`: Stack canary protection
- `-fstack-clash-protection`: Prevents stack clash attacks

**Linking Security:**
- `-Wl,-z,relro,-z,now`: Full RELRO (immediate binding + read-only GOT)
- `-Wl,-z,noexecstack`: Non-executable stack
- `-Wl,--as-needed`: Link only required libraries

**Control Flow:**
- `-fcf-protection`: Intel CET support (if available)
- `-fno-strict-overflow`: Prevent signed overflow exploitation

**Code Quality:**
- `-Wall -Wextra -Wpedantic -Werror`: All warnings are errors
- `-Wformat -Wformat-security`: Format string vulnerability prevention

### Build System

**Automatic File Discovery**: The Makefile uses wildcards to discover all `.cpp` files in `src/` and `tests/` directories. Adding new source files requires no Makefile changes.

**Dependency Tracking**: Uses GCC's `-MMD -MP` flags to auto-generate and include `.d` dependency files, ensuring proper rebuilds when headers change.

**Color Output**: Uses ANSI escape codes for colored build output (green for success, yellow for warnings, etc.).

## Development Patterns

### Adding New Functionality

When adding features to IP/date extraction:
1. Add new regex pattern to the appropriate `extract_*()` function
2. Test with various log formats in `tests/test_main.cpp`
3. Update `sample.log` with example inputs
4. Verify both normal and `--stats` modes work correctly

### Code Quality Standards

- **Input Validation**: All external input (file paths, regex patterns) must be validated
- **Exception Safety**: Use RAII; catch exceptions at main() boundary
- **Prefer Standard Library**: Use `std::string`, `std::vector`, `std::regex` over C equivalents
- **No Raw Pointers**: Use smart pointers or stack allocation
- **Const Correctness**: Mark read-only parameters as `const&`

### Security Considerations

- **Regex Complexity**: Be cautious of regex patterns that could cause ReDoS (Regular Expression Denial of Service)
- **File I/O**: Always check file open status; use RAII (ifstream closes on destruction)
- **Integer Overflow**: When calculating table widths or counts, use `size_t` and check for overflow
- **Memory Safety**: No buffer overflows possible due to std::string usage
- **Format Strings**: Never use user input directly in format strings
- **JSON Output**: All strings are properly escaped using `json_escape()` to prevent injection
  - Escapes quotes, backslashes, and control characters
  - Control characters (< 0x20) converted to Unicode escape sequences
  - IP addresses and dates treated as untrusted input

## Testing

### Test Structure

Tests are in `tests/test_main.cpp` and cover:
- IPv4/IPv6 extraction edge cases
- Date parsing for all supported formats
- File parsing with temporary test file
- Statistics aggregation with multiple IPs
- Version information

### Running Specific Tests

To debug a specific component:
```bash
# Add focused test to test_main.cpp
# Rebuild and run
make test

# Or run test binary directly for more control
./bin/test_ipdigger
```

## Common Tasks

### Adding a New Date Format

1. Add regex pattern to `extract_date()` in `src/ipdigger.cpp`
2. Add corresponding `strptime` format string
3. Add test case in `test_extract_date()` in `tests/test_main.cpp`
4. Test with `make test`

### Modifying Table Output

Table formatting is in `print_table()` and `print_stats_table()` functions. Both:
- Calculate column widths dynamically based on content
- Use `std::setw()` for alignment
- Draw separator lines with dashes

### Handling Large Files

Current implementation reads line-by-line (memory efficient) but stores all entries in memory (for sorting and statistics). For extremely large files:
- Consider streaming output (don't store all entries)
- For `--stats` mode, use online statistics algorithms
- Add optional line limit flag

## Debian Package Details

- **Package name**: `ipdigger`
- **Version**: Controlled by `VERSION` variable in Makefile
- **Architecture**: `amd64` (hardcoded)
- **Install location**: `/usr/local/bin/ipdigger`
- **Control file**: Auto-generated during `make deb`

To update version: Change `VERSION := 1.0.0` in Makefile, then `make deb`.

## Known Limitations

- **Date Parsing**: Syslog format lacks year; uses current year
- **IPv6 Regex**: Simplified pattern; some exotic IPv6 formats may not match
- **Timezone Handling**: Timestamps parsed to local timezone
- **Binary Files**: Will attempt to parse; may produce garbage output
