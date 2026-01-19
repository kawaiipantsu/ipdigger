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

# Test with compressed files
./bin/ipdigger /var/log/nginx/access.log.gz    # Gzip compressed
./bin/ipdigger /var/log/auth.log.bz2           # Bzip2 compressed
./bin/ipdigger /var/log/syslog.xz              # XZ compressed
./bin/ipdigger "/var/log/*.log*"               # Mixed compressed/uncompressed
```

## Architecture

### Core Components

**src/ipdigger.cpp**: Core functionality
- `extract_ip_addresses()`: Regex-based extraction of IPv4 and IPv6 addresses (uses RegexCache)
- `extract_date()`: Multi-format date parsing (ISO8601, Apache, Syslog, etc.) (uses RegexCache)
- `parse_file()`: Line-by-line file parsing and IP/date extraction (adds filename to entries)
- `parse_file_parallel()`: Multi-threaded chunk-based parsing for large files (1GB+)
- `parse_chunk()`: Parse a file chunk with progress updates
- `calculate_chunks()`: Split file into thread-safe chunk boundaries
- `parse_files()`: Parse multiple files with error handling (continues on file errors)
- `expand_glob()`: POSIX glob pattern expansion for wildcards (*, ?, [...])
- `generate_statistics()`: Aggregate IPs with first/last seen and count
- `print_table()`: ASCII table output showing unique IPs (shows filename column if multiple files)
- `print_stats_table()`: ASCII table output for statistics view
- `print_json()`: JSON output for unique IPs (includes filename field if multiple files)
- `print_stats_json()`: JSON output for statistics
- `json_escape()`: Helper function for secure JSON string escaping
- `get_regex_cache()`: Returns singleton RegexCache with pre-compiled patterns

**src/progress.cpp**: Progress tracking
- `ProgressTracker`: Thread-safe progress bar with ETA calculation
- Real-time updates with transfer rate (MB/s) and estimated time remaining
- Fixed-width formatting to prevent terminal line wrapping
- Double-check locking pattern to reduce mutex contention
- 500ms throttling to prevent screen flicker

**src/compression.cpp**: Compressed file support
- `detect_compression()`: Detect compression type from file extension
- `is_compressed()`: Check if file is compressed
- `get_file_size()`: Get file size in bytes
- `LineReader`: Abstract interface for reading lines (compressed or not)
- `RegularFileReader`: Reader for uncompressed files (wraps std::ifstream)
- `GzipReader`: Reader for .gz files (uses zlib)
- `Bzip2Reader`: Reader for .bz2 files (uses libbz2)
- `XzReader`: Reader for .xz files (uses liblzma)
- `create_reader()`: Factory function to create appropriate reader

**include/compression.h**: Compression API
- `CompressionType`: Enum for compression types (NONE, GZIP, BZIP2, XZ)
- `LineReader`: Abstract interface with getline(), eof(), tell() methods
- Concrete reader classes for each compression format
- Helper functions for compression detection and file size

**src/main.cpp**: CLI interface
- Command-line argument parsing
- Glob pattern expansion for file paths
- `--stats` mode switching
- `--output-json` flag handling
- `--single-threaded` and `--threads` flags for performance control
- Thread count detection via `std::thread::hardware_concurrency()`
- Compression detection and handling
- Error handling and user feedback
- Multi-file processing coordination
- Dispatches to parallel or single-threaded parsing based on file size, thread count, and compression status
- User notification when compressed files force single-threaded mode

**include/ipdigger.h**: Public API
- `IPEntry`: Single IP occurrence with line number, timestamp, and filename
- `IPStats`: Aggregated statistics per unique IP
- `RegexCache`: Pre-compiled regex patterns (IPv4, IPv6, dates, search patterns)
- Glob expansion and multi-file parsing functions
- Parallel parsing function declarations

**include/progress.h**: Progress tracking API
- `ProgressTracker`: Thread-safe progress tracker class
- Methods: `init()`, `add_bytes()`, `display()`, `finish()`
- Helper methods: `get_percentage()`, `get_eta_seconds()`, `format_bytes()`, `format_time()`

**include/config.h**: Configuration
- `parsing_threads`: Thread count for parsing (0 = auto-detect)
- `chunk_size_mb`: Chunk size for parallel parsing (default: 10MB)

**include/correlation.h**: IP Correlation API
- `CorrelationType`: Enum for correlation types (NONE, USER, HOST, CUSTOM)
- `CorrelationSettings`: Configuration for correlation operations (type, field names, regex, delimiter info)
- `FormatDetectionResult`: Result of CSV format auto-detection (delimiter, header, field count, field map)
- CSV detection and parsing functions
- Correlation value extraction functions (user, host, custom regex)
- Grouped output functions (table and JSON)

**src/correlation.cpp**: IP Correlation implementation
- `detect_csv_format()`: Auto-detect CSV delimiter and header from sample lines (80% consistency threshold)
- `parse_csv_line()`: State machine CSV parser with quote handling (handles embedded delimiters)
- `map_field_names()`: Build field_name → column_index map from CSV header (case-insensitive)
- `extract_field_value()`: Lookup field value by name from parsed CSV line
- `extract_domain()`: Extract root domain from FQDN (handles special TLDs like .co.uk)
- `correlate_user()`: Extract user field value from CSV line
- `correlate_host()`: Extract host field value with optional domain extraction
- `correlate_custom()`: Apply regex pattern to extract custom correlation value
- `extract_correlation_value()`: Unified dispatcher for all correlation types
- `print_stats_table_grouped_by_correlation()`: Table output grouped by correlation value
- `print_stats_json_grouped_by_correlation()`: JSON output grouped by correlation value
- Supports comma, semicolon, pipe, and tab delimiters
- Aggregates multiple correlation values per IP (comma-separated)
- Groups sorted by total event count (descending)

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

### Compressed File Support

IPDigger automatically detects and processes compressed log files with no special flags required.

**Supported Formats**:
- **Gzip (.gz)**: Uses zlib library for decompression
- **Bzip2 (.bz2)**: Uses libbz2 library for decompression
- **XZ (.xz)**: Uses liblzma library for decompression

**Auto-detection**:
- Compression type detected by file extension (case-insensitive)
- Mixed compressed and uncompressed files supported in glob patterns
- Example: `ipdigger "/var/log/*.log*"` processes both `.log` and `.log.gz` files

**Implementation Details**:
- **LineReader abstraction**: Uniform API for all file types (compressed or not)
- **Single-threaded only**: Compressed files cannot use parallel parsing (streams don't support seeking)
- **Progress tracking**: Shows compressed bytes processed (approximate for compressed files)
- **Error handling**: Clear error messages for corrupted compressed files
- **Memory efficient**: 64KB decompression buffers, line-by-line processing

**Performance**:
- Gzip: ~30-60 MB/s (compressed size)
- Bzip2: ~15-30 MB/s (slower decompression)
- XZ: ~40-80 MB/s (fastest decompression)

**Dependencies** (automatically linked in Makefile):
- zlib1g-dev (for gzip)
- libbz2-dev (for bzip2)
- liblzma-dev (for XZ)

**Usage Examples**:
```bash
# Single compressed file
./bin/ipdigger /var/log/nginx/access.log.gz

# Mixed compressed/uncompressed with glob
./bin/ipdigger "/var/log/nginx/*.log*"

# With options (works exactly like uncompressed files)
./bin/ipdigger --top-limit 10 --enrich-geo /var/log/auth.log.bz2
./bin/ipdigger --output-json /var/log/syslog.xz
```

**Files Modified**:
- `include/compression.h`: Compression types and LineReader interface
- `src/compression.cpp`: Reader implementations (~700 lines)
- `src/ipdigger.cpp`: Modified parse_file() to use LineReader
- `src/main.cpp`: Compression detection and parallel parsing disable
- `Makefile`: Added -lz -lbz2 -llzma linker flags

### Performance Architecture

IPDigger is optimized for processing large log files (1GB+) with multi-threaded parsing:

**Regex Pre-compilation (3-5x speedup)**:
- `RegexCache` struct holds pre-compiled regex patterns (IPv4, IPv6, date formats)
- Compiled once at startup, eliminating millions of per-line compilations
- Thread-safe: passed by const reference to all extraction functions
- Singleton pattern via `get_regex_cache()` ensures single instance

**Multi-threaded Parsing (8-20x speedup on 8+ cores)**:
- **Chunk-based parallelism**: Large files split into 10MB chunks (configurable)
- **Line boundary handling**: Chunks aligned on newlines to prevent split lines
- **Thread pool pattern**: Worker threads fetch chunks atomically via `std::atomic<size_t>`
- **Lock-free progress**: `std::atomic` counters for bytes processed
- **Result merging**: Thread-local results merged after all threads complete

**Progress Tracking**:
- **Thread-safe updates**: `ProgressTracker` uses `std::atomic` for counters and `std::mutex` for display
- **Double-check locking**: Reduces mutex contention (check time elapsed before acquiring lock)
- **Fixed-width formatting**: All numbers use `std::setw()` to prevent terminal line wrapping
- **Smart throttling**: Updates every 500ms or 1% progress to prevent flicker
- **ETA calculation**: `(total_bytes - processed_bytes) / bytes_per_second`

**Thread Safety Patterns**:
- `std::atomic<size_t>` for work distribution (`chunk_index.fetch_add(1)`)
- `std::mutex` + `std::lock_guard` for console output
- `const RegexCache&` passed to all threads (read-only, no synchronization needed)
- Thread-local `std::vector<IPEntry>` for results (no sharing until merge)

**Heuristics**:
- Only use parallel parsing for files > 10MB (avoid thread overhead)
- Respect `--single-threaded` flag for debugging
- Auto-detect CPU cores via `std::thread::hardware_concurrency()`
- Progress bar disabled in JSON mode (to prevent corrupting output)

**Configuration** (`~/.ipdigger/settings.conf`):
```ini
[performance]
parsing_threads = 0        # 0 = auto-detect (recommended)
chunk_size_mb = 10         # Chunk size for parallel parsing
```

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

**Current implementation** (v1.3.0+):
- Multi-threaded chunk-based parsing for files >10MB
- Pre-compiled regex patterns (3-5x faster)
- Real-time progress bar with ETA
- Memory-efficient: reads line-by-line, stores aggregated statistics only

**Performance testing**:
```bash
# Generate test file
for i in {1..10000000}; do
  echo "$(date -Iseconds) 192.168.1.$((RANDOM % 255)) GET /api/test HTTP/1.1"
done > /tmp/large.log

# Benchmark parallel parsing
time ./bin/ipdigger --top-10 /tmp/large.log

# Compare with single-threaded
time ./bin/ipdigger --single-threaded --top-10 /tmp/large.log

# Test with custom thread count
time ./bin/ipdigger --threads 8 --top-10 /tmp/large.log
```

**Memory considerations**:
- Statistics mode (`--stats`) stores aggregated data per unique IP (memory efficient)
- Progress tracker uses atomic counters (no memory overhead)
- Chunk-based parsing processes data in 10MB chunks (configurable)

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
