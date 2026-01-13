# Changelog

All notable changes to IPDigger will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/yourusername/ipdigger/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/yourusername/ipdigger/releases/tag/v1.0.0
