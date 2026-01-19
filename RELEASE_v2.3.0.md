# IPDigger v2.3.0 - Compressed Files, Group-By Analysis & THUGSred TI

## 🗜️ Compressed File Support, Network-Level Analysis & Threat Intelligence

This is a **minor release** introducing compressed file support, group-by analysis features, and THUGSred Threat Intelligence integration. IPDigger can now process .gz/.bz2/.xz files directly, group IPs by network attributes for rapid threat assessment, and check against curated VPN and threat intelligence lists.

## New Features

🗜️ **Compressed File Support**
- Automatic detection and processing by file extension
- Supports gzip (.gz), bzip2 (.bz2), and XZ (.xz) formats
- Stream-based decompression for memory efficiency
- Single-threaded parsing for compressed files (streams don't support seeking)
- Progress tracking shows compressed bytes processed
- Seamless integration with all existing features and filters
- No special flags needed - just pass the compressed file path

📊 **Group-By Analysis**
- `--group-by-asn` - Group IPs by Autonomous System Number
- `--group-by-country` - Group IPs by country code
- `--group-by-org` - Group IPs by organization/ISP name
- Auto-enables `--enrich-geo` enrichment when group-by is used
- Output shows group headers with indented IP details
- Groups sorted by total count (descending)
- Supports both table and JSON output formats
- Perfect for network-level threat assessment

🛡️ **THUGSred Threat Intelligence** (`--enrich-thugsred-ti`)
- Downloads and caches 7 curated threat intelligence CSV files:
  - **CINSBadRep**: CINS Army BadRep list (known malicious IPs)
  - **PeerDrop**: Spamhaus DROP/EDROP list (serious threats)
  - **NordVPN_v4/v6**: NordVPN exit node lists (IPv4/IPv6)
  - **Mullvad_v4/v6**: Mullvad VPN exit node lists (IPv4/IPv6)
  - **PhishTank**: PhishTank phishing sites (last 7 days)
- Supports both individual IPs and CIDR ranges (IPv4 and IPv6)
- Smart caching with configurable TTL (default: 24 hours)
- Each list has dedicated output field showing "Yes"/"No" match status
- Field names automatically derived from list filenames
- Unique SHA256-based cache filenames prevent conflicts
- Configurable via `~/.ipdigger/settings.conf` (`thugsred_ti_cache_hours`)

📚 **Extended Help System**
- `--help` - Concise option list without examples (quick reference)
- `--help-extended` - Comprehensive help with examples and documentation
- Clear notes about enrichment features requiring online access
- Better organized and easier to navigate

## Usage Examples

### Compressed File Processing
```bash
# Process gzip compressed log
ipdigger /var/log/nginx/access.log.gz

# Process bzip2 compressed log with top 10
ipdigger --top-limit 10 /var/log/auth.log.bz2

# Process XZ compressed logs with glob pattern
ipdigger "/var/log/*.log.xz"

# Combine with enrichment
ipdigger --enrich-geo --enrich-thugsred-ti /var/log/nginx/access.log.gz

# Time-range filtering on compressed file
ipdigger --time-range "24hours," --no-private /var/log/auth.log.bz2
```

### Group-By Analysis
```bash
# Group by country to see geographic distribution
ipdigger --group-by-country /var/log/nginx/access.log

# Group by ASN to identify top attacking networks
ipdigger --group-by-asn --top-limit 10 /var/log/auth.log

# Group by organization with JSON output
ipdigger --group-by-org --output-json /var/log/nginx/access.log

# Combined with threat detection
ipdigger --group-by-country --detect-login --top-limit 20 /var/log/auth.log

# Compressed file + group-by
ipdigger --group-by-asn --no-private /var/log/auth.log.gz
```

Example output:
```
=== Group: AS15169 (Google LLC) - Total: 247 ===
| IP Address   | Count | First Seen          | Last Seen           |
|-------------|-------|---------------------|---------------------|
| 8.8.8.8     |   125 | 2026-01-19 10:00:00 | 2026-01-19 15:30:00 |
| 8.8.4.4     |   122 | 2026-01-19 10:05:00 | 2026-01-19 15:25:00 |

=== Group: AS13335 (Cloudflare, Inc.) - Total: 189 ===
| IP Address   | Count | First Seen          | Last Seen           |
|-------------|-------|---------------------|---------------------|
| 1.1.1.1     |   189 | 2026-01-19 09:00:00 | 2026-01-19 16:00:00 |
```

### THUGSred Threat Intelligence
```bash
# Check IPs against threat intelligence lists
ipdigger --enrich-thugsred-ti /var/log/auth.log

# Combine TI with group-by for network-level threat assessment
ipdigger --enrich-thugsred-ti --group-by-country --top-limit 20 /var/log/nginx/access.log

# Filter to recent activity and check against TI
ipdigger --time-range "24hours," --enrich-thugsred-ti --no-private /var/log/auth.log

# Full analysis: compressed + TI + grouping
ipdigger --group-by-asn --enrich-thugsred-ti --no-private /var/log/auth.log.gz

# Combine with other enrichment
ipdigger --enrich-geo --enrich-thugsred-ti --enrich-abuseipdb --output-json /var/log/auth.log
```

Example output:
```
| IP Address   | Count | CINSBadRep | PeerDrop | NordVPN_v4 | Mullvad_v4 | PhishTank |
|-------------|-------|------------|----------|------------|------------|-----------|
| 45.67.89.12 |   247 | Yes        | No       | No         | No         | Yes       |
| 192.0.2.50  |   125 | No         | No       | Yes        | No         | No        |
| 198.51.100.1|    89 | No         | No       | No         | No         | No        |
```

### Combined Features
```bash
# Compressed file + group-by + TI + time-range
ipdigger --time-range "24hours," \
         --group-by-country \
         --enrich-thugsred-ti \
         --no-private \
         /var/log/auth.log.gz

# Full security analysis on compressed logs
ipdigger --enrich-geo \
         --enrich-thugsred-ti \
         --enrich-abuseipdb \
         --group-by-asn \
         --top-limit 20 \
         --output-json \
         /var/log/nginx/access.log.gz > report.json
```

## Technical Highlights

### Compressed File Support
- **Stream-based abstraction**: LineReader interface with compression-specific implementations
- **Auto-detection**: Determines compression type by file extension
- **Memory efficient**: Processes compressed data in streams, no full decompression needed
- **Libraries used**: zlib (gzip), libbz2 (bzip2), liblzma (XZ)
- **Progress tracking**: Shows compressed bytes processed for approximate progress
- **Error handling**: Graceful handling of corrupted files with clear error messages
- **Thread safety**: Single-threaded parsing for compressed files (streams don't support parallel seeks)

### Group-By Analysis
- **Auto-enrichment**: Automatically enables `--enrich-geo` when needed
- **Network-level insights**: Aggregate IPs by ASN, country, or organization
- **Sorted output**: Groups sorted by total count (descending)
- **Nested display**: Group headers with indented IP details
- **JSON support**: Structured JSON output with grouped data
- **Performance**: Efficient grouping and sorting even for large datasets

### THUGSred TI Integration
- **CIDR matching**: Supports both individual IPs and CIDR ranges (IPv4/IPv6)
- **Smart caching**: Downloads lists only when older than configured TTL
- **Unique filenames**: SHA256 hash of URL prevents cache collisions
- **Parallel checking**: Checks all 7 lists concurrently for performance
- **Always visible**: All TI fields always shown (with "Yes"/"No" status)
- **Configurable**: TTL adjustable via `~/.ipdigger/settings.conf`

### Code Changes
- New `include/compression.h` and `src/compression.cpp` with LineReader abstraction
- Enhanced `src/ipdigger.cpp` with 6 new group-by output functions
- Updated `src/enrichment.cpp` with THUGSred TI enrichment functions
- Modified `src/main.cpp` with new CLI flags and help system
- Extended `include/enrichment.h` with TI enrichment structures
- Updated `src/config.cpp` with `thugsred_ti_cache_hours` setting

## Breaking Changes

**None!** This release is fully backward compatible with v2.2.0. All existing commands work exactly as before.

## Bug Fixes

- **Bzip2 EOF Handling**: Fixed BZ_STREAM_END handling to properly process remaining data before marking EOF
- **Group-by-org Field**: Corrected to use "org" field from geo enrichment (was incorrectly using "netname" from WHOIS)
- **ASN Prefix Duplication**: Removed duplicate "AS" prefix in ASN grouping (enrichment already includes it)
- **Cache Filename Collisions**: THUGSred TI lists now use unique SHA256-based cache filenames
- **TI Field Visibility**: All THUGSred TI fields now always visible in output (with "No" if not matched)
- **Time-Range Help Text**: Clarified that "24hours," means "last 24 hours" (not ",24hours")

## Installation

### Debian/Ubuntu
```bash
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v2.3.0/ipdigger_2.3.0_amd64.deb
sudo dpkg -i ipdigger_2.3.0_amd64.deb
```

### From Source
```bash
git clone https://github.com/kawaiipantsu/ipdigger.git
cd ipdigger
git checkout v2.3.0
make
sudo make install
```

## Requirements

- GCC 7+ or Clang 5+ (C++17)
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev (for gzip compression)
- libbz2-dev (for bzip2 compression)
- liblzma-dev (for XZ compression)

## Compatibility

Works seamlessly with all existing flags:
- **Enrichment**: `--enrich-geo`, `--enrich-rdns`, `--enrich-abuseipdb`, `--enrich-whois`, `--enrich-ping`, `--enrich-tls`, `--enrich-http`, `--enrich-thugsred-ti`
- **Group-By**: `--group-by-asn`, `--group-by-country`, `--group-by-org`
- **Analysis**: `--detect-login`, `--detect-ddos`, `--detect-spray`, `--detect-scan`, `--detect-bruteforce`
- **Filtering**: `--no-private`, `--no-reserved`, `--geo-filter-none-eu`, `--geo-filter-none-gdpr`, `--time-range`
- **Performance**: `--threads`, `--single-threaded`
- **Output**: `--output-json`, `--output-geomap`

## Use Cases

**Compressed Log Analysis:**
```bash
# Process archived logs without manual decompression
ipdigger /var/log/nginx/access.log.gz

# Analyze rotated logs with enrichment
ipdigger --enrich-geo --enrich-abuseipdb /var/log/auth.log.bz2

# Process multiple compressed files
ipdigger --top-limit 20 "/var/log/*.log.xz"
```

**Network-Level Threat Assessment:**
```bash
# Identify top attacking networks by ASN
ipdigger --group-by-asn --detect-login --top-limit 10 /var/log/auth.log

# Geographic distribution of threats
ipdigger --group-by-country --enrich-abuseipdb /var/log/nginx/access.log

# Organization-level analysis
ipdigger --group-by-org --no-private --top-limit 20 /var/log/auth.log
```

**VPN and Proxy Detection:**
```bash
# Detect VPN exit nodes and malicious IPs
ipdigger --enrich-thugsred-ti /var/log/auth.log

# Find VPN users by country
ipdigger --enrich-thugsred-ti --group-by-country /var/log/nginx/access.log

# Filter recent VPN activity
ipdigger --time-range "24hours," --enrich-thugsred-ti --no-private /var/log/auth.log
```

**Incident Response:**
```bash
# Quick analysis of recent compressed logs
ipdigger --time-range "24hours," \
         --enrich-thugsred-ti \
         --enrich-abuseipdb \
         --group-by-asn \
         /var/log/auth.log.gz

# Full threat assessment
ipdigger --enrich-geo \
         --enrich-thugsred-ti \
         --enrich-abuseipdb \
         --group-by-country \
         --detect-login \
         --top-limit 30 \
         --output-json \
         /var/log/auth.log > incident-report.json
```

**Data Export:**
```bash
# Export TI analysis to JSON
ipdigger --enrich-thugsred-ti --output-json /var/log/auth.log.gz > ti-report.json

# Create GeoJSON map with TI data
ipdigger --enrich-geo --enrich-thugsred-ti --output-geomap /var/log/auth.log > threat-map.geojson

# Group-by analysis in JSON format
ipdigger --group-by-asn --enrich-thugsred-ti --output-json /var/log/nginx/access.log > asn-report.json
```

## What's Changed

### New Features
- Compressed file support (.gz, .bz2, .xz) with auto-detection
- Group-by analysis (ASN, country, organization)
- THUGSred Threat Intelligence integration (7 curated lists)
- Extended help system (--help vs --help-extended)

### New CLI Flags
- `--group-by-asn` - Group IPs by Autonomous System Number
- `--group-by-country` - Group IPs by country code
- `--group-by-org` - Group IPs by organization/ISP name
- `--enrich-thugsred-ti` - Check against THUGSred threat intelligence lists
- `--help-extended` - Show comprehensive help with examples

### Output Enhancements
- Group-by output: Group headers with indented IP details
- THUGSred TI fields: CINSBadRep, PeerDrop, NordVPN_v4, NordVPN_v6, Mullvad_v4, Mullvad_v6, PhishTank
- Compressed file support: Transparent processing with progress tracking

### Configuration
- `thugsred_ti_cache_hours` - Configure TI list cache TTL in `~/.ipdigger/settings.conf`

## Migration Guide

**No migration needed!** Just upgrade and start using the new features:

```bash
# Process compressed files (no special flags needed)
ipdigger /var/log/nginx/access.log.gz

# Group IPs by network attributes
ipdigger --group-by-asn /var/log/auth.log

# Check against threat intelligence
ipdigger --enrich-thugsred-ti /var/log/auth.log

# Use extended help for comprehensive documentation
ipdigger --help-extended
```

## Performance Notes

- **Compressed files**: Use single-threaded parsing (streams don't support seeking), ~30-80 MB/s depending on format
- **Regular files**: Continue to use multi-threaded parallel parsing, ~400-800 MB/s on 8+ cores
- **Group-by**: Efficient aggregation even for large datasets with millions of IPs
- **THUGSred TI**: Smart caching minimizes network overhead, lists downloaded only when stale

## Contributors

- kawaiipantsu @ THUGSred Hacking Community
- Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>

## Links

- **GitHub Repository**: https://github.com/kawaiipantsu/ipdigger
- **Release Page**: https://github.com/kawaiipantsu/ipdigger/releases/tag/v2.3.0
- **Issues**: https://github.com/kawaiipantsu/ipdigger/issues
- **Full Changelog**: https://github.com/kawaiipantsu/ipdigger/compare/v2.2.0...v2.3.0

---

**Released**: 2026-01-19
**Version**: 2.3.0
**Tag**: v2.3.0
