# Changelog

All notable changes to IPDigger will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.2.0]: https://github.com/yourusername/ipdigger/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/yourusername/ipdigger/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/yourusername/ipdigger/releases/tag/v1.0.0
