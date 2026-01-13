# IPDigger v1.1.0 Release Notes

Released: 2026-01-13

## Overview

IPDigger v1.1.0 introduces a powerful IP enrichment system that transforms basic log analysis into comprehensive IP intelligence gathering. This release adds GeoIP lookups, threat intelligence, reverse DNS resolution, and a flexible configuration system.

## Highlights

### IP Enrichment System
The new enrichment system provides deep intelligence about every IP address found in your logs:
- **GeoIP Lookups**: Identify country, city, region, and ASN information using MaxMindDB
- **Threat Intelligence**: Detect potentially malicious IPs with integrated threat detection
- **Reverse DNS**: Resolve IP addresses to hostnames for better context
- **Parallel Processing**: Fast enrichment with configurable concurrency (default: 3 parallel requests)

### Configuration Management
Customize IPDigger to match your workflow:
- Configuration file at `~/.ipdigger/settings.conf`
- Enable/disable specific enrichment features
- Configure cache TTL and parallel processing limits
- Set up MaxMind license key for automatic database updates

### Intelligent Caching
Performance optimization through smart caching:
- Local cache directory at `~/.ipdigger/cache`
- 24-hour default TTL (configurable)
- Significantly reduces API calls and processing time
- Automatic cache invalidation

### MaxMindDB Integration
Seamless GeoIP database management:
- Automatic download of GeoLite2 databases
- Support for custom MaxMind license keys
- Configurable database directory
- No manual setup required

## Installation

### From Debian Package
```bash
wget https://github.com/yourusername/ipdigger/releases/download/v1.1.0/ipdigger_1.1.0_amd64.deb
sudo dpkg -i ipdigger_1.1.0_amd64.deb
```

### From Source
```bash
git clone https://github.com/yourusername/ipdigger.git
cd ipdigger
git checkout v1.1.0
make
sudo make install
```

## Usage Examples

### Basic Enrichment
```bash
# Enrich IPs with all available data
ipdigger --enrich /var/log/nginx/access.log

# Show statistics with enrichment
ipdigger --enrich --stats /var/log/auth.log

# JSON output with enrichment
ipdigger --enrich --output-json /var/log/access.log
```

### Configuration
Create `~/.ipdigger/settings.conf`:
```ini
[enrichment]
geo = true
threat = true
rdns = true
parallel_requests = 5

[cache]
enabled = true
ttl_hours = 48

[maxmind]
license_key = YOUR_LICENSE_KEY_HERE
auto_download = true
```

## What's Changed

### Added
- IP enrichment system with GeoIP, threat intelligence, and rDNS
- Configuration file support with flexible settings
- Caching system for improved performance
- MaxMindDB integration with automatic database management
- New command-line flag: `--enrich` to enable enrichment
- Parallel processing for fast multi-IP enrichment
- Enhanced output formats to display enrichment data

### Dependencies
New dependencies in this release:
- `libcurl4-openssl-dev` - HTTP client for API requests
- `libssl-dev` - Cryptographic operations
- `libmaxminddb-dev` - GeoIP database support

Install dependencies on Debian/Ubuntu:
```bash
sudo apt-get install libcurl4-openssl-dev libssl-dev libmaxminddb-dev
```

### Technical Changes
- Added `EnrichmentData` structure to `IPEntry` and `IPStats`
- Integrated nlohmann/json library for JSON parsing
- Multi-threaded architecture for concurrent enrichment
- Automatic creation of config and cache directories

## Upgrade Notes

### Upgrading from 1.0.0
This is a backward-compatible release. Existing commands will continue to work exactly as before. The new enrichment features are opt-in via the `--enrich` flag or configuration file.

### Breaking Changes
None. All v1.0.0 functionality is preserved.

## Known Issues
- Syslog date format lacks year information (uses current year)
- Some exotic IPv6 formats may not be detected
- Enrichment requires internet connectivity for threat intelligence APIs

## Future Roadmap
- Support for custom threat intelligence feeds
- Export enriched data to various formats (CSV, SQLite)
- Real-time log monitoring mode
- Web-based visualization dashboard

## Contributors
Special thanks to all contributors who made this release possible!

## Links
- [Download Debian Package](https://github.com/yourusername/ipdigger/releases/download/v1.1.0/ipdigger_1.1.0_amd64.deb)
- [Full Changelog](CHANGELOG.md)
- [Documentation](README.md)
- [Report Issues](https://github.com/yourusername/ipdigger/issues)

## Checksums

SHA256 checksums will be provided after package upload.
