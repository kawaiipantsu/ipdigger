# IPDigger v2.1.0 - HTTP Enrichment & GeoJSON Mapping

## 🌍 Geographic Visualization & Web Server Discovery

This is a **minor release** introducing HTTP server enrichment, GeoJSON map export, and enhanced filtering options. IPDigger can now discover web servers, extract TLS/HTTP metadata, and export data directly to mapping tools for geographic visualization.

## New Features

🌐 **HTTP Server Enrichment** (`--enrich-http`)
- Automatic port detection: tries ports 443 (HTTPS), 80 (HTTP), and 3000
- HTTP status code extraction (e.g., 200, 404, 500)
- Redirect chain tracking (e.g., "308->200" shows redirect followed by success)
- Server header extraction (nginx/1.18.0, Apache/2.4.41, etc.)
- Content-Security-Policy (CSP) detection
- HTML page title extraction from response body
- `--follow-redirects` flag to follow HTTP redirects (optional)
- Real-time progress bar during HTTP checks
- Full integration with existing enrichment and filtering flags

🗺️ **GeoJSON Map Output** (`--output-geomap`)
- Export IP data as valid GeoJSON FeatureCollection format
- Point features with latitude/longitude from MaxMind GeoLite2 City database
- Rich property data: IP address, count, timestamps, login events, all enrichment fields
- Automatic filtering: only includes IPs with valid coordinates
- Compatible with all major mapping tools:
  - Leaflet.js - Popular JavaScript mapping library
  - Mapbox GL JS - Interactive vector maps
  - QGIS - Professional GIS software
  - Google Maps - GeoJSON layer support
  - Kepler.gl - Geospatial data visualization
- Requires `--enrich-geo` flag to provide coordinate data
- Stackable with other flags for advanced filtering and enrichment

🎯 **Enhanced Filtering Options**
- `--top-limit <N>` - Flexible top N filtering (replaces fixed --top-10/20/50/100)
- `--limit <N>` - Show only latest N entries from the log
- `--no-reserved` - Comprehensive reserved IP filtering:
  - Private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fe80::/10)
  - Loopback addresses (127.0.0.0/8, ::1/128)
  - Link-local (169.254.0.0/16, fe80::/10)
  - Multicast (224.0.0.0/4, ff00::/8)
  - Documentation/TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)

## Usage Examples

### HTTP Server Discovery
```bash
# Discover web servers on top 10 IPs
ipdigger --enrich-http --top-limit 10 /var/log/nginx/access.log

# Check TLS certificates and HTTP servers together
ipdigger --enrich-tls --enrich-http --top-limit 20 /var/log/nginx/access.log

# Find servers outside EU with CSP analysis
ipdigger --geo-filter-none-eu --enrich-http --top-limit 10 /var/log/nginx/access.log
```

Example output:
```
| IP Address   | Port | Status | Server        | CSP | Title           |
|-------------|------|--------|---------------|-----|-----------------|
| 203.0.113.5 | 443  | 200    | nginx/1.18.0  | Yes | Welcome Page    |
| 198.51.100.1| 80   | 308->200| Apache/2.4.41| No  | Redirected Site |
```

### GeoJSON Map Creation
```bash
# Create interactive attack map with threat intelligence
ipdigger --enrich-geo --enrich-abuseipdb --output-geomap /var/log/auth.log > attack-map.geojson

# Map top 50 traffic sources
ipdigger --enrich-geo --top-limit 50 --output-geomap /var/log/nginx/access.log > traffic-map.geojson

# Non-EU traffic visualization
ipdigger --geo-filter-none-eu --output-geomap /var/log/auth.log > non-eu-traffic.geojson

# Comprehensive map with all enrichment
ipdigger --enrich-geo --enrich-abuseipdb --enrich-whois \
         --detect-login --output-geomap /var/log/auth.log > full-analysis.geojson
```

Example GeoJSON output:
```json
{
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "geometry": {
        "type": "Point",
        "coordinates": [121.4737, 31.2304]
      },
      "properties": {
        "ip_address": "45.67.89.12",
        "count": 247,
        "first_seen": "2024-01-13 10:00:00",
        "last_seen": "2024-01-13 15:30:00",
        "cc": "CN",
        "country": "China",
        "city": "Shanghai",
        "abuseScore": "95"
      }
    }
  ]
}
```

### Enhanced Filtering
```bash
# Show latest 50 entries with full enrichment
ipdigger --enrich-geo --enrich-rdns --limit 50 /var/log/auth.log

# Top 30 IPs by count
ipdigger --top-limit 30 /var/log/nginx/access.log

# Filter all reserved IPs (more comprehensive than --no-private)
ipdigger --no-reserved --enrich-geo /var/log/auth.log
```

## Technical Highlights

### HTTP Enrichment
- Uses libcurl for robust HTTP/HTTPS requests
- Automatic TLS verification and certificate handling
- Port detection order: 443 (HTTPS) → 80 (HTTP) → 3000 (dev)
- Redirect chain tracking with `--follow-redirects` option
- Server header parsing for version detection
- CSP header presence detection for security analysis
- HTML title extraction from `<title>` tags
- Progress bar with real-time updates

### GeoJSON Export
- Valid GeoJSON FeatureCollection format (RFC 7946)
- Point geometry with [longitude, latitude] coordinates
- Properties include all enrichment data fields
- Automatic coordinate validation and filtering
- Compatible with GeoJSON specification 1.0
- Works with any GeoJSON-compatible tool

### Code Changes
- Enhanced `src/enrichment.cpp` with HTTP server detection functions
- Added GeoJSON export function to `src/ipdigger.cpp`
- Updated `src/main.cpp` with new CLI flags and output mode
- Extended `include/enrichment.h` with HTTP enrichment structures
- Added filtering functions for reserved IP ranges

## Breaking Changes

**None!** This release is fully backward compatible with v2.0.0. All existing commands work exactly as before.

## Installation

### Debian/Ubuntu
```bash
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v2.1.0/ipdigger_2.1.0_amd64.deb
sudo dpkg -i ipdigger_2.1.0_amd64.deb
```

### From Source
```bash
git clone https://github.com/kawaiipantsu/ipdigger.git
cd ipdigger
git checkout v2.1.0
make
sudo make install
```

## Requirements

- GCC 7+ or Clang 5+ (C++17)
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev

## Compatibility

Works seamlessly with all existing flags:
- Enrichment: `--enrich-geo`, `--enrich-rdns`, `--enrich-abuseipdb`, `--enrich-whois`, `--enrich-ping`, `--enrich-tls`
- Analysis: `--detect-login`, `--search`, `--search-regex`
- Filtering: `--no-private`, `--no-reserved`, `--geo-filter-none-eu`, `--geo-filter-none-gdpr`
- Performance: `--threads`, `--single-threaded`
- Output: `--output-json`, `--output-geomap`

## Use Cases

**Web Server Analysis:**
```bash
# Discover web servers and check configurations
ipdigger --enrich-http --enrich-tls --top-limit 20 /var/log/nginx/access.log

# Find misconfigured servers (no CSP)
ipdigger --enrich-http --top-limit 50 /var/log/nginx/access.log | grep "CSP | No"

# Check for expired certificates
ipdigger --enrich-tls --top-limit 50 /var/log/nginx/access.log
```

**Geographic Visualization:**
```bash
# Create interactive attack map
ipdigger --enrich-geo --enrich-abuseipdb --output-geomap /var/log/auth.log > attack-map.geojson

# Visualize traffic distribution
ipdigger --enrich-geo --top-limit 100 --output-geomap /var/log/nginx/access.log > traffic.geojson

# Map failed login attempts
ipdigger --enrich-geo --detect-login --output-geomap /var/log/auth.log > failed-logins.geojson
```

**Security Analysis:**
```bash
# Full security assessment with HTTP and TLS
ipdigger --enrich-geo --enrich-abuseipdb --enrich-tls --enrich-http \
         --detect-login --top-limit 20 /var/log/auth.log

# Find non-EU attackers with web servers
ipdigger --geo-filter-none-eu --enrich-http --detect-login /var/log/auth.log
```

**Data Export:**
```bash
# Export comprehensive JSON with HTTP data
ipdigger --enrich-geo --enrich-rdns --enrich-http --output-json /var/log/nginx/access.log > report.json

# Create GeoJSON for external visualization tools
ipdigger --enrich-geo --enrich-abuseipdb --output-geomap /var/log/auth.log > map.geojson
```

## What's Changed

### New Features
- HTTP server enrichment with port detection and metadata extraction
- GeoJSON map export for geographic visualization
- Flexible `--top-limit <N>` and `--limit <N>` filtering
- Comprehensive `--no-reserved` IP filtering

### New CLI Flags
- `--enrich-http` - Enable HTTP server enrichment
- `--follow-redirects` - Follow HTTP redirects
- `--output-geomap` - Export as GeoJSON format
- `--top-limit <N>` - Show top N IPs by count
- `--limit <N>` - Show latest N entries
- `--no-reserved` - Exclude all reserved IPs

### Output Enhancements
- HTTP enrichment columns: Port, Status, Server, CSP, Title
- GeoJSON FeatureCollection format with Point geometries
- JSON output includes `http_port`, `http_status`, `http_server`, `http_csp`, `http_title` fields

## Migration Guide

**No migration needed!** Just upgrade and start using the new features:

```bash
# Enable HTTP enrichment on existing commands
ipdigger --enrich-http /var/log/nginx/access.log

# Export to GeoJSON map format
ipdigger --enrich-geo --output-geomap /var/log/auth.log > map.geojson

# Use flexible top limit instead of fixed flags
ipdigger --top-limit 30 /var/log/nginx/access.log  # instead of --top-20 or --top-50
```

## Contributors

- kawaiipantsu @ THUGSred Hacking Community
- Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>

## Links

- **GitHub Repository**: https://github.com/kawaiipantsu/ipdigger
- **Release Page**: https://github.com/kawaiipantsu/ipdigger/releases/tag/v2.1.0
- **Issues**: https://github.com/kawaiipantsu/ipdigger/issues
- **Full Changelog**: https://github.com/kawaiipantsu/ipdigger/compare/v2.0.0...v2.1.0

---

**Released**: 2026-01-19
**Version**: 2.1.0
**Tag**: v2.1.0
