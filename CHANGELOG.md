# Changelog

All notable changes to IPDigger will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-01-19

### Added
- **HTTP Server Enrichment** (`--enrich-http`): Discover web servers running on IP addresses
  - Automatic port detection: tries ports 443 (HTTPS), 80 (HTTP), and 3000 in sequence
  - HTTP status code extraction (e.g., 200, 404, 500)
  - Redirect chain display (e.g., "308->200" for redirect followed by success)
  - Server header extraction (e.g., "nginx/1.18.0", "Apache/2.4.41")
  - Content-Security-Policy (CSP) detection - flags whether CSP header is present
  - HTML page title extraction from response body
  - `--follow-redirects` flag to follow HTTP redirects (optional, disabled by default)
  - Full integration with existing enrichment and filtering flags
  - Progress bar with real-time updates during HTTP checks
  - JSON output includes `http_port`, `http_status`, `http_server`, `http_csp`, `http_title` fields
- **GeoJSON Map Output** (`--output-geomap`): Export IP data as GeoJSON for mapping visualization
  - Valid GeoJSON FeatureCollection format compatible with all mapping tools
  - Point features with latitude/longitude coordinates from MaxMind GeoLite2 City database
  - Rich property data: IP address, count, timestamps, login data, all enrichment fields
  - Automatic filtering: only includes IPs with valid coordinates
  - Compatible mapping tools: Leaflet.js, Mapbox GL JS, QGIS, Google Maps, Kepler.gl
  - Requires `--enrich-geo` flag to provide coordinate data
  - Stackable with other flags: `--enrich-abuseipdb`, `--detect-login`, `--top-limit`, `--geo-filter-*`
- **Enhanced Filtering Options**: More flexible control over result sets
  - `--top-limit <N>`: Show only top N IPs sorted by count (flexible alternative to fixed --top-10/20/50/100)
  - `--limit <N>`: Show only latest N entries from the log (useful for recent activity)
  - `--no-reserved`: Comprehensive filtering of all reserved IP ranges
    - Includes private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fe80::/10)
    - Loopback addresses (127.0.0.0/8, ::1/128)
    - Link-local addresses (169.254.0.0/16, fe80::/10)
    - Multicast addresses (224.0.0.0/4, ff00::/8)
    - Documentation/TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    - More comprehensive than `--no-private` (which only filters RFC 1918 ranges)

### Changed
- **CLI Interface**: Added new flags for HTTP enrichment, GeoJSON output, and flexible filtering
- **Output Formats**: Table output includes HTTP enrichment columns when `--enrich-http` is used
- **Documentation**: Comprehensive examples for HTTP enrichment, GeoJSON mapping, and new filtering options

### Improved
- **Use Case Coverage**: Better support for network discovery, web server analysis, and geographic visualization
- **Mapping Integration**: Direct export to GeoJSON enables powerful visual analysis of IP distributions
- **Security Analysis**: HTTP enrichment reveals web server configurations, CSP policies, and TLS setups
- **Flexibility**: `--top-limit <N>` and `--limit <N>` provide more granular control over result sets

### Examples
```bash
# Discover web servers and check TLS certificates
ipdigger --enrich-http --enrich-tls --top-limit 10 /var/log/nginx/access.log

# Create interactive attack map with threat intelligence
ipdigger --enrich-geo --enrich-abuseipdb --output-geomap /var/log/auth.log > attack-map.geojson

# Find top 20 IPs outside EU with HTTP server details
ipdigger --geo-filter-none-eu --enrich-http --top-limit 20 /var/log/nginx/access.log

# Show latest 50 entries with full enrichment
ipdigger --enrich-geo --enrich-rdns --limit 50 /var/log/auth.log

# Export comprehensive map data for visualization
ipdigger --enrich-geo --enrich-abuseipdb --detect-login --output-geomap /var/log/auth.log > map.geojson
```

## [2.0.0] - 2026-01-14

### Added
- **Multi-Threaded Parsing** (`--threads`, `--single-threaded`): High-performance parallel file processing
  - Automatic CPU core detection for optimal thread count (via `std::thread::hardware_concurrency()`)
  - Chunk-based parallelism: Splits large files into 10MB chunks (configurable)
  - Thread-safe line boundary handling to prevent split lines across chunks
  - 3-5x speedup from regex pre-compilation for all files
  - 8-20x speedup from multi-threading on 8+ core systems for large files (1GB+)
  - Smart heuristics: Only uses parallel parsing for files >10MB to avoid thread overhead
  - `--threads N` flag to manually specify thread count
  - `--single-threaded` flag to force single-threaded mode for debugging/compatibility
- **Regex Pre-compilation System**: Massive performance improvement
  - `RegexCache` structure with pre-compiled patterns (IPv4, IPv6, date formats, search patterns)
  - Compiled once at startup, eliminating millions of per-line compilations
  - Thread-safe: passed by const reference to all extraction functions
  - Singleton pattern via `get_regex_cache()` ensures single instance
- **Progress Bar with ETA**: Real-time parsing progress visualization
  - `ProgressTracker` class with thread-safe atomic counters and mutex-protected display
  - Fixed-width formatting to prevent terminal line wrapping
  - Progress bar format: `[====>    ] 35% 350MB/ 1.0GB  25MB/s  0m26s filename.log`
  - Shows: progress bar (25 chars), percentage, bytes processed, transfer rate, ETA, filename
  - Double-check locking pattern to reduce mutex contention
  - Smart throttling: Updates every 500ms or 1% progress to prevent screen flicker
  - Automatically disabled in JSON output mode to prevent corrupting output
  - Only shown for files >10KB to avoid overhead on small files
- **Performance Configuration**: User control over threading behavior
  - `[performance]` section in `~/.ipdigger/settings.conf`
  - `parsing_threads = 0` (0 = auto-detect CPU cores, or specify count)
  - `chunk_size_mb = 10` (chunk size for parallel parsing in megabytes)

### Changed
- **Parser Architecture**: Complete rewrite for parallelism
  - Added `parse_file_parallel()` for chunk-based multi-threaded parsing
  - Added `parse_chunk()` to process individual chunks with progress updates
  - Added `calculate_chunks()` to split files into thread-safe boundaries
  - Enhanced `parse_file()` to use RegexCache and maintain single-threaded compatibility
  - All extraction functions now accept `const RegexCache&` parameter
- **Thread Safety**: Lock-free and mutex-protected operations
  - `std::atomic<size_t>` for work distribution (`chunk_index.fetch_add(1)`)
  - `std::atomic` counters for bytes processed (lock-free progress tracking)
  - `std::mutex` + `std::lock_guard` for console output synchronization
  - Thread-local `std::vector<IPEntry>` for results (no sharing until merge)
- **Main Loop**: Enhanced dispatching logic
  - Thread count detection and configuration loading
  - Dispatches to parallel or single-threaded parsing based on file size and thread count
  - Proper progress tracking initialization with context

### Improved
- **Performance**: Dramatically faster processing for all file sizes
  - Small files (<10MB): 3-5x faster from regex pre-compilation
  - Large files (1GB+): 8-20x faster on 8-core systems (combined regex + threading)
  - Memory-efficient: Chunk-based processing limits memory usage
  - Scalable: Performance scales with CPU core count
- **User Experience**: Better visibility into long-running operations
  - Real-time progress bar with accurate ETA calculations
  - Transfer rate helps estimate performance
  - Filename display shows which file is being processed
  - No screen flicker or line wrapping issues
- **Code Quality**: Modern C++ practices
  - RAII pattern with smart resource management
  - Thread-safe singleton for RegexCache
  - Proper const-correctness throughout
  - Comprehensive error handling

### Technical Details
- Added new files:
  - `include/regex_cache.h`: RegexCache structure definition
  - `include/progress.h`: ProgressTracker class declaration
  - `src/progress.cpp`: Progress tracking implementation
- Enhanced existing files:
  - `src/ipdigger.cpp`: Parallel parsing implementation, RegexCache integration
  - `src/main.cpp`: CLI flags, thread count detection, dispatching logic
  - `include/ipdigger.h`: Updated function signatures for RegexCache
  - `include/config.h`: Added `parsing_threads` and `chunk_size_mb` fields
  - `src/config.cpp`: Parse performance section from settings.conf
  - `tests/test_main.cpp`: Updated all tests to use RegexCache
- Thread safety patterns:
  - Lock-free atomic operations for counters
  - Double-check locking for display updates
  - Const reference passing for shared read-only data
  - Thread-local storage for results
- Performance optimizations:
  - Pre-compiled regex patterns eliminate compilation overhead
  - Chunk-based processing enables parallelism
  - Fixed-width formatting prevents terminal issues
  - Smart throttling reduces system calls

### Breaking Changes
None. This release is fully backward compatible with v1.3.0. The default behavior uses automatic parallelism, but `--single-threaded` flag maintains previous behavior.

## [1.3.0] - 2026-01-14

### Added
- **Search Functionality**: Filter logs by literal strings or regex patterns
  - `--search <string>`: Case-insensitive literal string search
  - `--search-regex <pattern>`: Case-insensitive regex pattern search
  - New **SearchHits** column shows count of matching lines per IP
  - Full integration with existing enrichment and filtering flags
  - JSON output includes `search_hits` field when search is used

### Improved
- **Statistics Tracking**: Search hit counts tracked per IP address
- **Output Formatting**: Smart column display (SearchHits only shown when search is active)
- **Documentation**: Comprehensive search feature documentation and examples

## [1.2.0] - 2026-01-13

### Added
- **WHOIS Enrichment** (`--enrich-whois`): Native WHOIS lookups with automatic referral following
  - Extracts network name (netname) for identifying network owners
  - Retrieves abuse contact email addresses for reporting
  - Displays CIDR ranges for network boundaries
  - Shows administrative contact information
  - Queries multiple regional registries (IANA, ARIN, RIPE, APNIC, LACNIC, AFRINIC)
  - Automatic referral following from IANA to appropriate RIRs
  - 1-second rate limiting to respect WHOIS servers
- **Login Detection** (`--detect-login`): Intelligent authentication event tracking
  - Detects failed login attempts using 35+ keyword patterns
  - Identifies successful login events
  - Aggregates login statistics per IP address
  - Displays as "OK:X F:Y" format in table output (X=successful, Y=failed)
  - Supports various log formats (SSH, FTP, web auth, etc.)
  - Keywords include: failed, denied, wrong password, invalid user, blocked, banned, etc.
- **AbuseIPDB Threat Intelligence** (`--enrich-abuseipdb`): Security threat scoring
  - Integrates with AbuseIPDB API for threat intelligence
  - Extracts abuse confidence score (0-100 risk rating)
  - Shows usage type (Data Center, ISP, Hosting, etc.)
  - Displays total reports count from community
  - Includes ISP information
  - Progress bar with elapsed time tracking
  - 100ms rate limiting for API compliance
- **Private IP Filtering** (`--no-private`): Exclude internal networks
  - Filters out RFC 1918 private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Removes loopback addresses (127.0.0.0/8)
  - Excludes link-local addresses (169.254.0.0/16)
  - Filters IPv6 private ranges (fc00::/7, fe80::/10)
  - Useful for focusing on external/public IP addresses
- **Top N Filtering**: Focus on most active IP addresses
  - `--top-10`: Show only top 10 IPs by occurrence count
  - `--top-20`: Show only top 20 IPs by occurrence count
  - `--top-50`: Show only top 50 IPs by occurrence count
  - `--top-100`: Show only top 100 IPs by occurrence count
  - Sorted by count in descending order
- **Enhanced Progress Indicators**: Real-time enrichment feedback
  - Progress bars for all enrichment operations (GeoIP, RDNS, AbuseIPDB, WHOIS)
  - Percentage completion display
  - Elapsed time in seconds
  - Format: `[====>    ] X/Y (Z%) Ts`

### Changed
- **MaxMind Authentication**: Updated to use Account ID + License Key
  - Changed from legacy license-only authentication
  - Now requires both `account_id` and `license_key` in config
  - Uses HTTP Basic Authentication for database downloads
  - Updated API endpoint to new MaxMind URL format
- **JSON Output Enhancement**: Added login statistics fields
  - `login_success_count`: Number of successful login events
  - `login_failed_count`: Number of failed login events
  - Always present in output (0 if --detect-login not used)
- **Column Optimization**: Renamed "country_code" to "cc" for space efficiency
- **Configuration Structure**: Cleaned up default settings file
  - Removed deprecated generic `--enrich` flag
  - Split into specific enrichment flags per provider
  - Streamlined settings.conf with only essential sections

### Improved
- **Enrichment Architecture**: Modular per-provider enrichment system
  - Each provider has dedicated `--enrich-*` flag
  - Can combine multiple enrichment sources
  - Example: `--enrich-geo --enrich-whois --enrich-abuseipdb`
- **User Feedback**: Better visibility into long-running operations
  - All enrichment operations show progress
  - Elapsed time helps estimate completion
  - Clear error messages for failed lookups

### Technical Details
- Added socket programming for native WHOIS queries (port 43)
- Implemented WHOIS response parsing for multiple RIR formats
- Enhanced IPEntry and IPStats structures with login tracking fields
- Added AbuseIPDB API integration with HTTP headers
- Implemented login detection with case-insensitive keyword matching
- Added private IP range checking for IPv4 and IPv6

## [1.1.0] - 2026-01-13

### Added
- **IP Enrichment System**: Comprehensive IP address intelligence gathering
  - GeoIP lookups using MaxMindDB for country, city, and ASN information
  - Threat intelligence integration for identifying malicious IPs
  - Reverse DNS (rDNS) lookups for hostname resolution
  - Configurable parallel processing for fast enrichment of multiple IPs
- **Configuration Management**: User-configurable settings system
  - Configuration file support at `~/.ipdigger/settings.conf`
  - Customizable enrichment options (geo, threat, rDNS)
  - Configurable cache settings and TTL
  - MaxMindDB automatic download with license key support
- **Caching System**: Intelligent caching for performance
  - Local cache directory at `~/.ipdigger/cache`
  - Configurable TTL (default 24 hours)
  - Reduces API calls and improves response time for repeated queries
- **MaxMindDB Integration**: Automatic GeoIP database management
  - Auto-download of GeoLite2 databases
  - Configurable database directory
  - Support for custom MaxMind license keys

### Changed
- Enhanced `IPEntry` structure to include optional enrichment data
- Enhanced `IPStats` structure to include optional enrichment data
- Improved output formats to display enrichment information when available

### Technical Details
- Added `libcurl` dependency for HTTP requests
- Added `libssl` and `libcrypto` dependencies for secure operations
- Added `libmaxminddb` dependency for GeoIP lookups
- Integrated nlohmann/json library for JSON parsing
- Added multi-threaded processing for parallel enrichment requests

## [1.0.0] - 2024-01-13

### Added
- Initial release of IPDigger
- **Core IP Extraction**: Extract IPv4 and IPv6 addresses from log files
- **Date/Timestamp Parsing**: Support for multiple common log formats
  - ISO 8601 / RFC3339 format
  - Apache/Nginx log format
  - Syslog format
  - Common date/time format
- **Glob Pattern Support**: Process multiple files using wildcards
  - Support for `*.log`, `*.txt`, and other patterns
  - Recursive file matching
  - Graceful handling of unreadable files
- **Output Modes**:
  - ASCII table output for human-readable results
  - JSON output for machine-readable results
  - Statistics mode showing first seen, last seen, and occurrence count
- **Command-Line Interface**:
  - `--stats` flag for statistical analysis
  - `--output-json` flag for JSON output format
  - `--help` for usage information
  - `--version` for version information
- **Security Features**:
  - Compiled with comprehensive security hardening flags
  - Stack protection (canaries, clash protection)
  - Position Independent Executable (PIE) with ASLR
  - Full RELRO (read-only relocations)
  - Non-executable stack
  - Control flow protection
  - Format string protection
  - Fortified source functions
- **Build System**:
  - Makefile with automatic dependency tracking
  - Color-coded build output
  - Debian package generation (`make deb`)
  - Install/uninstall targets
  - Comprehensive test suite
- **Project Structure**:
  - Clean separation of headers and implementation
  - Test suite with multiple test cases
  - Sample log file for testing

### Dependencies
- GCC 7+ or Clang 5+ with C++17 support
- GNU Make
- dpkg-deb (for Debian package creation)

[2.1.0]: https://github.com/kawaiipantsu/ipdigger/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/kawaiipantsu/ipdigger/compare/v1.3.0...v2.0.0
[1.3.0]: https://github.com/kawaiipantsu/ipdigger/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/kawaiipantsu/ipdigger/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/kawaiipantsu/ipdigger/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kawaiipantsu/ipdigger/releases/tag/v1.0.0
