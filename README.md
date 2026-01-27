# IPDigger

```
     ___________ ____________
    |     +      )._______.-'
     `----------'

       IP Digger v3.0.0
  Your swiss armyknife tool for IP addresses

         by kawaiipantsu
    THUGSred Hacking Community
       https://thugs.red
```

A secure C++ log analysis tool for extracting and enriching IP addresses from log files.

## Features

- 🔍 **IP Extraction**: IPv4 and IPv6 from any log format
- 📊 **Statistics**: Count, first/last seen per IP
- 🔗 **IP Correlation**: Map IPs to users, hostnames, or custom patterns from CSV logs (auto-detects format)
- 🔎 **Search**: Filter logs by literal strings or regex patterns with hit counts per IP
- ⏰ **Time-Range Filtering**: Filter entries by timestamp (Unix, ISO 8601, relative times like "24hours")
- 📊 **Group-By Analysis**: Group IPs by ASN, country, or organization for network-level insights
- 🌍 **GeoIP**: MaxMind country/city/ASN data with latitude/longitude
- 🗺️ **Map Visualization**: Export GeoJSON for mapping tools (Leaflet, Mapbox, QGIS)
- 🔐 **Login Detection**: Track authentication success/failures
- 🚨 **Attack Detection**: Detect DDoS, password spray, port scanning, and brute force patterns
- 🛡️ **Threat Intel**: AbuseIPDB abuse scoring, Tor exit nodes, and THUGSred TI lists (VPN/threats)
- 📋 **WHOIS**: Network ownership and abuse contacts
- 🌐 **Reverse DNS**: Hostname resolution
- 🏓 **Ping Detection**: Response time measurement and host availability
- 🔒 **TLS/SSL**: Certificate information (CN, issuer, dates, version, key size)
- 🌐 **HTTP Detection**: Web server discovery (port, status, server, CSP, title)
- 🎯 **Filtering**: Reserved IPs, IPv4/IPv6, top N IPs, geographic filtering (EU/GDPR regions)
- 📦 **Formats**: ASCII tables, JSON output, or GeoJSON map
- ⚡ **High Performance**: Multi-threaded parsing for large files (1GB+) with progress bar and ETA
- 🗜️ **Compressed Files**: Auto-detects and processes .gz, .bz2, and .xz files
- 🔒 **Secure**: Full security hardening (PIE, RELRO, stack protection)

## Installation

### Debian/Ubuntu

**Multi-Architecture Support**: IPDigger v3.0.0 provides packages for three architectures:

```bash
# AMD/Intel 64-bit (most common - desktops, servers, cloud)
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v3.0.0/ipdigger_3.0.0_amd64.deb
sudo dpkg -i ipdigger_3.0.0_amd64.deb

# ARM 64-bit (Raspberry Pi 3/4/5, AWS Graviton, Apple Silicon via Linux VM)
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v3.0.0/ipdigger_3.0.0_arm64.deb
sudo dpkg -i ipdigger_3.0.0_arm64.deb

# Intel 32-bit (legacy systems)
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v3.0.0/ipdigger_3.0.0_i386.deb
sudo dpkg -i ipdigger_3.0.0_i386.deb
```

### From Source
```bash
git clone https://github.com/kawaiipantsu/ipdigger.git
cd ipdigger
make
sudo make install
```

### Requirements
- GCC 7+ or Clang 5+ (C++17)
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev (for gzip compression)
- libbz2-dev (for bzip2 compression)
- liblzma-dev (for XZ compression)

## Quick Start

```bash
# Basic usage
ipdigger /var/log/nginx/access.log

# Multiple files
ipdigger "/var/log/*.log"

# Read from stdin (pipe support)
echo "192.168.1.1" | ipdigger
cat ip_list.txt | ipdigger
grep "Failed" /var/log/auth.log | ipdigger --detect-login

# With enrichment
ipdigger --enrich-geo --enrich-whois /var/log/auth.log

# Find top attackers
ipdigger --detect-login --top-limit 20 --no-private /var/log/auth.log

# Geographic filtering (non-EU traffic)
ipdigger --geo-filter-none-eu /var/log/auth.log

# Create interactive map visualization
ipdigger --enrich-geo --output-geomap /var/log/auth.log > map.geojson

# Check TLS certificates and HTTP servers
ipdigger --enrich-tls --enrich-http --top-limit 10 /var/log/nginx/access.log

# Check host availability
ipdigger --enrich-ping --top-limit 10 /var/log/nginx/access.log

# Search for specific patterns
ipdigger --search "Failed password" /var/log/auth.log

# Compressed files (auto-detected)
ipdigger /var/log/nginx/access.log.gz
ipdigger --top-limit 10 /var/log/auth.log.bz2

# Group-by analysis
ipdigger --group-by-country /var/log/nginx/access.log
ipdigger --group-by-asn --top-limit 10 /var/log/auth.log
ipdigger --group-by-org --output-json /var/log/nginx/access.log

# Threat intelligence checking
ipdigger --enrich-thugsred-ti /var/log/auth.log
ipdigger --enrich-thugsred-ti --group-by-country --top-limit 20 /var/log/nginx/access.log

# Time range filtering (last 24 hours)
ipdigger --time-range "24hours," /var/log/auth.log

# Full analysis
ipdigger --enrich-geo --enrich-whois --enrich-abuseipdb \
         --detect-login --top-limit 10 --output-json /var/log/auth.log
```

## IP Correlation

IP Correlation maps IP addresses to other fields (users, hostnames, or custom patterns) from structured log data. Perfect for security analysis and user tracking.

### Correlation Types

**User Correlation** - Track which users accessed from which IPs:
```bash
# Map IPs to usernames/emails from CSV logs
ipdigger --correlate-user username auth.csv
ipdigger --correlate-user email --output-json login_log.csv
```

**Host Correlation** - Map IPs to hostnames or domains:
```bash
# Map IPs to hostnames
ipdigger --correlate-host hostname server_log.csv

# Extract root domain from FQDNs (mail.example.com -> example.com)
ipdigger --correlate-host fqdn --extract-domain dns.csv
```

**Custom Regex** - Extract custom patterns:
```bash
# Correlate by HTTP method
ipdigger --correlate-custom 'method="(GET|POST)"' web.log

# Correlate by status code
ipdigger --correlate-custom 'status=(\d+)' nginx.log

# Correlate by action
ipdigger --correlate-custom 'action=(\w+)' app.log
```

### Features
- **Auto-detection**: CSV format with comma, semicolon, pipe, or tab delimiters
- **Header detection**: Automatically detects and uses header row
- **Multiple values**: IPs with multiple correlation values shown as comma-separated
- **Grouped output**: Results grouped by correlation value, sorted by event count
- **JSON support**: Full correlation data in JSON output

### Example Workflow

Sample CSV file:
```csv
timestamp,ip,user,action
2024-01-13 10:00:00,192.168.1.100,alice,login
2024-01-13 10:15:00,192.168.1.101,bob,login
2024-01-13 10:30:00,192.168.1.100,charlie,logout
```

Analysis:
```bash
ipdigger --correlate-user user login_audit.csv
```

Output:
```
User: alice, charlie (1 IP, 2 events)
================================================================================
| IP Address      | First Seen          | Last Seen           | Count |
| 192.168.1.100   | 2024-01-13 10:00:00 | 2024-01-13 10:30:00 |     2 |

User: bob (1 IP, 1 event)
================================================================================
| IP Address      | First Seen          | Last Seen           | Count |
| 192.168.1.101   | 2024-01-13 10:15:00 | 2024-01-13 10:15:00 |     1 |
```

### Use Cases
- **Security Analysis**: Find shared credentials (multiple users from same IP)
- **User Tracking**: Track which IPs each user accessed from
- **Network Mapping**: Map IPs to infrastructure by hostname or domain
- **Pattern Analysis**: Group by HTTP method, status code, or custom patterns

For detailed correlation documentation, run:
```bash
ipdigger --help-correlation
```

## Performance

IPDigger is optimized for processing large log files (1GB+) with multi-threaded parsing:

### Multi-Threaded Parsing
- **Automatic parallelism**: Detects CPU cores and uses optimal thread count
- **Chunk-based processing**: Splits large files into chunks for parallel processing
- **Progress tracking**: Real-time progress bar with transfer rate and ETA
- **Smart throttling**: Only shows updates every 500ms to prevent screen flicker

### Performance Features
```bash
# Auto-detect CPU cores (default behavior)
ipdigger /var/log/large-file.log

# Force single-threaded mode (debugging)
ipdigger --single-threaded /var/log/large-file.log

# Specify thread count manually
ipdigger --threads 8 /var/log/large-file.log
```

### Progress Bar
When processing large files (>10KB), IPDigger shows a progress bar:
```
[====>    ] 35% 350MB/ 1.0GB  25MB/s  26s access.log
```

The progress bar displays:
- **Progress bar**: Visual representation (25 chars)
- **Percentage**: Completion percentage
- **Bytes processed**: Current MB / Total GB
- **Transfer rate**: Processing speed in MB/s
- **ETA**: Estimated time remaining (minutes and seconds)
- **Filename**: Current file being processed (truncated to 30 chars)

**Note**: Progress bar is automatically disabled in JSON output mode (`--output-json`)

### Performance Improvements
- **3-5x faster**: Pre-compiled regex patterns eliminate per-line compilation overhead
- **8-20x faster**: Multi-threaded parsing on 8+ core systems for large files
- **Optimized I/O**: Memory-efficient chunk-based reading for files >1GB

## Usage

```
Usage: ipdigger [OPTIONS] <filename>
   or: ipdigger [OPTIONS] -
   or: <command> | ipdigger [OPTIONS]

Output Formats:
  --output-json      Output in JSON format
  --output-geomap    Output as GeoJSON map (requires --enrich-geo)

Enrichment:
  --enrich-geo       Enrich with geolocation data (MaxMind)
  --enrich-rdns      Enrich with reverse DNS lookups
  --enrich-abuseipdb Enrich with AbuseIPDB threat intelligence
  --enrich-whois     Enrich with WHOIS data (netname, abuse, CIDR, admin)
  --enrich-ping      Enrich with ping response time and availability
  --enrich-tls       Enrich with TLS certificate data (CN, issuer, dates, version, keysize)
  --enrich-http      Enrich with HTTP server data (port, status, server, CSP, title)
  --follow-redirects Follow HTTP redirects when using --enrich-http

Analysis:
  --detect-login     Detect and track login attempts (success/failed)
  --search <string>  Filter lines by literal string and count hits per IP
  --search-regex <pattern> Filter lines by regex pattern and count hits per IP

Filtering:
  --no-private           Exclude private/local network addresses
  --no-reserved          Exclude reserved IP addresses (private, loopback, multicast, etc.)
  --no-ipv4              Exclude IPv4 addresses
  --no-ipv6              Exclude IPv6 addresses
  --geo-filter-none-eu   Filter to show only IPs outside the EU (auto-enables --enrich-geo)
  --geo-filter-none-gdpr Filter to show only IPs outside GDPR regions (auto-enables --enrich-geo)
  --top-limit <N>        Show only top N IPs sorted by count
  --limit <N>            Show only latest N entries

Performance:
  --single-threaded      Force single-threaded parsing (disables parallelism)
  --threads <N>          Number of threads for parsing (default: auto-detect CPU cores)

Info:
  --help             Display help message
  --version          Display version information
```

## Examples

### Basic IP Extraction
```bash
ipdigger /var/log/nginx/access.log
```
```
| IP Address      | First Seen          | Last Seen           | Count |
|----------------|---------------------|---------------------|-------|
| 192.168.1.100  | 2024-01-13 08:15:23 | 2024-01-13 08:25:30 |     4 |
| 203.0.113.45   | 2024-01-13 08:17:12 | 2024-01-13 08:17:12 |     1 |
```

### Stdin/Pipe Support

IPDigger can read from stdin, making it perfect for Unix pipelines:

```bash
# Pipe a single IP
echo "192.168.1.1" | ipdigger

# Pipe a list of IPs
cat ip_list.txt | ipdigger --enrich-geo

# Filter logs first, then analyze
grep "Failed password" /var/log/auth.log | ipdigger --detect-login

# Chain with other commands
tail -1000 /var/log/nginx/access.log | ipdigger --no-private --top-limit 10

# From curl output
curl -s https://example.com/ip-list.txt | ipdigger --enrich-abuseipdb

# Using explicit stdin marker
cat /var/log/auth.log | ipdigger - --output-json

# Complex pipeline
awk '/Failed/ {print}' /var/log/auth.log | ipdigger --detect-login --enrich-geo --top-limit 5
```

### Compressed Files

IPDigger automatically detects and processes compressed log files. No special flags needed:

```bash
# Gzip compressed logs
ipdigger /var/log/nginx/access.log.gz

# Bzip2 compressed logs
ipdigger /var/log/auth.log.bz2

# XZ compressed logs
ipdigger /var/log/syslog.xz

# Mixed compressed and uncompressed files with glob patterns
ipdigger "/var/log/nginx/*.log*"

# Works with all options
ipdigger --top-limit 10 --enrich-geo /var/log/auth.log.gz
ipdigger --output-json /var/log/nginx/access.log.bz2
ipdigger --detect-ddos --detect-bruteforce /var/log/auth.log.xz
```

**Supported formats:**
- `.gz` (gzip) - ~30-60 MB/s
- `.bz2` (bzip2) - ~15-30 MB/s
- `.xz` (XZ) - ~40-80 MB/s

**Note:** Compressed files use single-threaded parsing only (streams don't support seeking). Regular files can still use parallel processing.

### Login Detection
```bash
ipdigger --detect-login /var/log/auth.log
```
```
| IP Address      | Count | Login        |
|----------------|-------|-------------|
| 203.0.113.45   |     8 | OK:0 F:8    |
| 8.8.8.8        |     3 | OK:3 F:0    |
```

### WHOIS Enrichment
```bash
ipdigger --enrich-whois /var/log/auth.log
```
```
| IP Address   | netname    | abuse                    | cidr                |
|-------------|------------|--------------------------|---------------------|
| 8.8.8.8     | GOGL       | network-abuse@google.com | 8.8.8.0 - 8.8.8.255 |
| 1.1.1.1     | APNIC-LABS | helpdesk@apnic.net       | 1.1.1.0 - 1.1.1.255 |
```

### GeoIP + Threat Intelligence
```bash
ipdigger --enrich-geo --enrich-abuseipdb --top-limit 10 /var/log/auth.log
```
```
| IP Address   | Country | City      | abuseScore | totalReports | isTor |
|-------------|---------|-----------|-----------|-------------|-------|
| 45.67.89.12 | CN      | Shanghai  | 95        | 247         | No    |
| 23.45.67.89 | RU      | Moscow    | 87        | 156         | Yes   |
```

### TLS Certificate Detection
```bash
ipdigger --enrich-tls --top-limit 10 /var/log/nginx/access.log
```
```
| IP Address   | CN              | Issuer        | Created       | Expires       | TLS Ver | KeySize |
|-------------|-----------------|---------------|---------------|---------------|---------|---------|
| 203.0.113.5 | example.com     | Let's Encrypt | 01/15/2026... | 04/15/2026... | TLSv1.3 | 2048    |
| 198.51.100.1| secure.site.com | DigiCert      | 12/01/2025... | 12/01/2026... | TLSv1.2 | 4096    |
```

### HTTP Server Discovery
```bash
ipdigger --enrich-http --top-limit 10 /var/log/nginx/access.log
```
```
| IP Address   | Port | Status | Server        | CSP | Title           |
|-------------|------|--------|---------------|-----|-----------------|
| 203.0.113.5 | 443  | 200    | nginx/1.18.0  | Yes | Welcome Page    |
| 198.51.100.1| 80   | 308->200| Apache/2.4.41| No  | Redirected Site |
```

The HTTP enrichment feature:
- **Port detection**: Tries ports 443, 80, 3000 in order
- **Status codes**: Shows HTTP status (200, 404, etc.) or redirect chain (308->200)
- **Server header**: Extracts web server version
- **CSP detection**: Checks if Content-Security-Policy header is present
- **Title extraction**: Captures HTML page title
- **Redirect following**: Use `--follow-redirects` to follow HTTP redirects

### Geographic Filtering
```bash
# Show only IPs outside the EU (27 countries)
ipdigger --geo-filter-none-eu /var/log/auth.log
```
```
| IP Address   | Country | City         | Count |
|-------------|---------|--------------|-------|
| 8.8.8.8     | US      | Mountain View|    12 |
| 45.67.89.12 | CN      | Shanghai     |     8 |
| 23.45.67.89 | RU      | Moscow       |     5 |
```

```bash
# Show only IPs outside GDPR-compliant regions (EU + EEA + UK + CH = 32 countries)
ipdigger --geo-filter-none-gdpr /var/log/nginx/access.log
```
```
| IP Address   | Country | Count |
|-------------|---------|-------|
| 8.8.8.8     | US      |    45 |
| 1.1.1.1     | AU      |    23 |
| 45.67.89.12 | CN      |    15 |
```

### Ping Detection
```bash
# Check host availability and response times
ipdigger --enrich-ping /var/log/nginx/access.log
```
```
| IP Address   | Count | Ping / Alive              |
|-------------|-------|---------------------------|
| 8.8.8.8     |    23 | avg: 21.5ms jitter: 0.2ms |
| 1.1.1.1     |    15 | avg: 15.3ms jitter: 1.1ms |
| 203.0.113.5 |     8 | DEAD                      |
```

The ping feature:
- **Progress bar** - Shows real-time progress while pinging hosts
- **Average ping time** - Mean response time over 3 ping attempts
- **Jitter** - Variation in response times (mdev/stddev)
- **DEAD status** - Shown for unreachable or unresponsive hosts

### GeoJSON Map Output
```bash
# Create GeoJSON for mapping tools
ipdigger --enrich-geo --output-geomap /var/log/auth.log > map.geojson
```

The GeoJSON output format:
- **Valid GeoJSON**: FeatureCollection format compatible with all mapping tools
- **Point features**: Each IP with coordinates becomes a map point
- **Rich properties**: Includes count, timestamps, login data, and all enrichment fields
- **Auto-filtering**: Only IPs with valid latitude/longitude coordinates are included
- **Coordinate source**: Uses MaxMind GeoLite2 City database for accurate coordinates

**Compatible mapping tools:**
- Leaflet.js - Popular JavaScript mapping library
- Mapbox GL JS - Interactive vector maps
- QGIS - Professional GIS software
- Google Maps - With GeoJSON layer support
- Kepler.gl - Geospatial data visualization
- Any tool supporting GeoJSON standard

**Example GeoJSON output:**
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

**Usage examples:**
```bash
# Create interactive attack map
ipdigger --enrich-geo --enrich-abuseipdb --output-geomap /var/log/auth.log > attacks.geojson

# Top 20 IPs on a map
ipdigger --enrich-geo --top-limit 20 --output-geomap /var/log/nginx/access.log > top-visitors.geojson

# Non-EU traffic map
ipdigger --geo-filter-none-eu --output-geomap /var/log/auth.log > non-eu-traffic.geojson
```

### Large File Processing
```bash
# Process large files (1GB+) with auto-threading
ipdigger --top-limit 20 /var/log/huge-access.log
```

When processing large files, IPDigger shows a progress bar:
```
[====>                    ] 35%   350MB/ 1.0GB   25MB/s   0m26s huge-access.log
```

Performance options:
```bash
# Force single-threaded mode for debugging
ipdigger --single-threaded /var/log/auth.log

# Specify thread count (default: auto-detect CPU cores)
ipdigger --threads 16 /var/log/huge-access.log

# Process multiple large files in parallel
ipdigger "/var/log/archive/*.log"
```

Performance benefits:
- **Auto-parallelism**: Automatically uses all available CPU cores
- **Real-time progress**: Shows processing speed, bytes processed, and ETA
- **3-5x faster**: Pre-compiled regex patterns
- **8-20x faster**: Multi-threaded parsing on 8+ core systems

### Search Filtering
```bash
# Search for specific patterns and count hits per IP
ipdigger --search "Failed password" /var/log/auth.log
```
```
| IP Address   | Count | SearchHits |
|-------------|-------|------------|
| 203.0.113.45|     8 |          8 |
| 8.8.8.8     |    15 |          3 |
| 1.1.1.1     |     5 |          0 |
```

```bash
# Use regex patterns for advanced filtering
ipdigger --search-regex "error|warning|critical" /var/log/nginx/error.log
```

The search feature:
- **--search** - Case-insensitive literal string matching
- **--search-regex** - Case-insensitive regex pattern matching
- **SearchHits column** - Shows count of lines matching the search criteria per IP
- **Count vs SearchHits** - Count shows total lines per IP, SearchHits shows matching lines
- **Filtering behavior** - All IPs are shown, but SearchHits highlights matching activity

### Time-Based Filtering

Filter log entries by timestamp to focus on specific time windows:

```bash
# Last 24 hours only
ipdigger --time-range ",24hours" /var/log/auth.log

# Specific date range
ipdigger --time-range "2024-01-13 00:00:00,2024-01-14 00:00:00" /var/log/auth.log

# Since deployment (open-ended)
ipdigger --time-range "2024-01-13 10:00:00," /var/log/app.log

# Last week's activity
ipdigger --time-range "7days,1day" /var/log/nginx/access.log

# Unix timestamp range
ipdigger --time-range "1705136400,1705222800" /var/log/auth.log

# Include entries without timestamps
ipdigger --time-range ",24hours" --include-no-timestamp /var/log/auth.log
```

**Supported time formats:**
- **Unix timestamp**: `1705136400`
- **ISO 8601/UTC**: `2024-01-13T12:34:56Z`
- **Common format**: `2024-01-13 12:34:56`
- **Date only**: `2024-01-13` (implies 00:00:00)
- **Relative times**: `30minutes`, `24hours`, `7days`, `1week`, `2months`, `1year`
  - Supported units: seconds, minutes, hours, days, weeks, months, years
  - Short forms: `s`, `m`, `h`, `d`, `w`, `mo`, `yr`

**Time range syntax:**
- `from,to` - Show entries between two times
- `,to` - Show entries up to time (from beginning)
- `from,` - Show entries from time onward (to end)

**Behavior:**
- Entries without timestamps are excluded by default
- Use `--include-no-timestamp` to include entries that have no date
- Relative times calculated from current time (now)
- Can be combined with other filters: `--no-private`, `--top-limit`, `--geo-filter-*`

### Attack Detection

Detect various network attack patterns based on temporal analysis of log events:

```bash
# Detect DDoS patterns (high volume in short time)
ipdigger --detect-ddos /var/log/nginx/access.log

# Detect brute force authentication attacks
ipdigger --detect-bruteforce --detect-login /var/log/auth.log

# Detect password spray attacks
ipdigger --detect-spray --detect-login /var/log/auth.log

# Detect port/network scanning
ipdigger --detect-scan /var/log/firewall.log

# Detect multiple attack types with custom threshold
ipdigger --detect-ddos --detect-bruteforce --threshold 20 --window 1m /var/log/auth.log

# Combine with enrichment for detailed analysis
ipdigger --detect-ddos --detect-scan --enrich-geo --enrich-abuseipdb /var/log/nginx/access.log

# Output with detection results
ipdigger --detect-ddos --detect-bruteforce --output-json /var/log/auth.log
```

**Detection Types:**
- **--detect-ddos** - High volume of requests (>= threshold) within a short time window
- **--detect-spray** - Password spray attacks: moderate failed logins distributed over time
- **--detect-scan** - Port/network scanning: many connections in very short time (< 1/5 of window)
- **--detect-bruteforce** - Brute force attacks: high failed login attempts in short window

**Configuration:**
- **--threshold N** - Event count threshold (default: 10)
- **--window <time>** - Time window for analysis (default: 5m)
  - Supported units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
  - Examples: `30s`, `5m`, `1h`, `7d`

**Output:**
- **Table format** - Shows DDoS/Spray/Scan/BruteForce columns with Yes/No values
- **JSON format** - Includes `is_ddos`, `is_spray`, `is_scan`, `is_bruteforce` boolean fields

**Detection Logic:**
- **DDoS**: Count >= threshold within time window
- **Brute Force**: Failed logins >= threshold within time window (requires --detect-login)
- **Spray**: Failed logins between 20-80% of threshold over longer period
- **Scan**: Count >= threshold within very short time (≤ window/5)

**Best Practices:**
- Combine `--detect-bruteforce` and `--detect-spray` with `--detect-login` for accurate results
- Adjust `--threshold` based on your environment (higher for busy servers)
- Use shorter `--window` for real-time detection, longer for historical analysis
- Combine with `--enrich-abuseipdb` to cross-reference with known malicious IPs

### JSON Output
```bash
ipdigger --enrich-geo --enrich-abuseipdb --output-json /var/log/auth.log
```
```json
{
  "statistics": [
    {
      "ip_address": "45.67.89.12",
      "first_seen": "2024-01-13 10:00:00",
      "last_seen": "2024-01-13 10:03:00",
      "count": 8,
      "first_timestamp": 1705136400,
      "last_timestamp": 1705136580,
      "login_success_count": 0,
      "login_failed_count": 8,
      "enrichment": {
        "cc": "CN",
        "country": "China",
        "city": "Shanghai",
        "asn": "AS4134",
        "org": "Chinanet",
        "abuseScore": "95",
        "usageType": "Data Center/Web Hosting/Transit",
        "totalReports": "247",
        "isp": "China Telecom",
        "isTor": "No"
      }
    }
  ],
  "total": 1
}
```

## Enrichment Data

IPDigger can enrich IP addresses with data from multiple sources:

### GeoIP (MaxMind)
- `cc` - Country code (ISO 2-letter, e.g., "US", "CN")
- `country` - Country name (e.g., "United States", "China")
- `city` - City name (e.g., "San Francisco", "Shanghai")
- `asn` - Autonomous System Number (e.g., "AS15169")
- `org` - Organization/ISP name
- `latitude` - Latitude coordinate (decimal degrees)
- `longitude` - Longitude coordinate (decimal degrees)

### AbuseIPDB
- `abuseScore` - Abuse confidence score (0-100)
- `usageType` - Type of IP usage (e.g., "Data Center/Web Hosting/Transit")
- `totalReports` - Total number of abuse reports
- `isp` - Internet Service Provider name
- `isTor` - Whether IP is a Tor exit node ("Yes" or "No")

### WHOIS
- `netname` - Network name
- `abuse` - Abuse contact email
- `cidr` - IP address range in CIDR notation
- `admin` - Administrative contact

### Reverse DNS
- `rdns` - Reverse hostname lookup result

### Ping
- `ping` - Response time and availability (e.g., "avg: 23.5ms jitter: 3.0ms" or "DEAD")

### TLS/SSL Certificate
- `tls_cn` - Common Name (CN) from certificate
- `tls_issuer` - Certificate issuer (e.g., "Let's Encrypt", "DigiCert")
- `tls_algorithm` - Signature algorithm (e.g., "sha256WithRSAEncryption")
- `tls_created` - Certificate creation date (MM/DD/YYYY HH:MM)
- `tls_expires` - Certificate expiration date (MM/DD/YYYY HH:MM)
- `tls_version` - TLS protocol version (e.g., "TLSv1.3", "TLSv1.2")
- `tls_keysize` - Public key size in bits (e.g., "2048", "4096")

### HTTP Server
- `http_port` - Port where web server was found (443, 80, or 3000)
- `http_status` - HTTP status code or redirect chain (e.g., "200", "308->200")
- `http_server` - Server header value (e.g., "nginx/1.18.0", "Apache/2.4.41")
- `http_csp` - Content-Security-Policy presence ("Yes" or "No")
- `http_title` - HTML page title

All enrichment fields are automatically included in both ASCII table and JSON output formats when the corresponding enrichment flag is used.

## Supported Log Formats

IPDigger automatically detects timestamps in various formats:

| Format          | Example                           | Common In               |
|----------------|-----------------------------------|------------------------|
| ISO 8601       | `2024-01-13T12:34:56Z`           | Application logs       |
| Common         | `2024-01-13 12:34:56`            | Generic logs           |
| Apache/Nginx   | `[13/Jan/2024:12:34:56 +0000]`   | Web server access logs |
| Syslog         | `Jan 13 12:34:56`                | System logs, auth.log  |
| Date only      | `2024-01-13`                     | Simple logs            |

**Supported IP formats:**
- IPv4: `192.168.1.1`, `8.8.8.8`
- IPv6: `2001:db8::1`, `::1`, `fe80::1`

**Works with any log file containing IP addresses:**
- `/var/log/nginx/access.log`
- `/var/log/apache2/access.log`
- `/var/log/auth.log`
- `/var/log/syslog`
- Custom application logs
- Firewall logs
- VPN logs

## Geographic Filtering

IPDigger includes built-in geographic filters to help with compliance analysis, threat intelligence, and traffic segmentation.

### Available Filters

| Filter | Regions Excluded | Countries | Use Case |
|--------|------------------|-----------|----------|
| `--geo-filter-none-eu` | EU member states only | 27 | Focus on non-EU traffic |
| `--geo-filter-none-gdpr` | EU + EEA + UK + Switzerland | 32 | Identify non-GDPR traffic |

### EU Member States (27)
Austria (AT), Belgium (BE), Bulgaria (BG), Croatia (HR), Cyprus (CY), Czech Republic (CZ), Denmark (DK), Estonia (EE), Finland (FI), France (FR), Germany (DE), Greece (GR), Hungary (HU), Ireland (IE), Italy (IT), Latvia (LV), Lithuania (LT), Luxembourg (LU), Malta (MT), Netherlands (NL), Poland (PL), Portugal (PT), Romania (RO), Slovakia (SK), Slovenia (SI), Spain (ES), Sweden (SE)

### GDPR-Compliant Regions (32)
EU27 + Iceland (IS), Liechtenstein (LI), Norway (NO), United Kingdom (GB), Switzerland (CH)

### Filter Behavior

- **Auto-enables enrichment**: Geographic filters automatically enable `--enrich-geo`
- **Benefit-of-doubt policy**: IPs without country codes (e.g., private IPs, lookup failures) are included in results
- **Stackable filters**: Can be combined with other filters like `--no-private` and `--top-N`
- **Works with both outputs**: Compatible with ASCII table and JSON output formats

### Example Usage

```bash
# Security: Find non-EU attackers
ipdigger --geo-filter-none-eu --detect-login --no-private /var/log/auth.log

# Compliance: Audit non-GDPR traffic
ipdigger --geo-filter-none-gdpr --enrich-geo --output-json /var/log/nginx/access.log

# Combined filtering: Top 10 non-EU IPs with threat intel
ipdigger --geo-filter-none-eu --enrich-abuseipdb --top-10 /var/log/auth.log
```

## Tor Exit Node Detection

IPDigger automatically detects Tor exit nodes when using `--enrich-abuseipdb`. This is useful for identifying anonymous traffic and potential security threats.

### How It Works

The `isTor` field is extracted from the AbuseIPDB API response and displays:
- **"Yes"** - IP is a known Tor exit node
- **"No"** - IP is not a Tor exit node

### Why It Matters

Tor exit nodes are commonly used for:
- **Anonymous attacks** - Hiding the attacker's true location
- **Credential stuffing** - Testing stolen credentials anonymously
- **Scanning and reconnaissance** - Automated attacks through Tor network
- **Policy violations** - Many organizations block Tor traffic

### Example Usage

```bash
# Identify Tor-based login attempts
ipdigger --enrich-abuseipdb --detect-login /var/log/auth.log

# Find Tor exit nodes with high abuse scores
ipdigger --enrich-abuseipdb --top-20 --no-private /var/log/auth.log

# Export Tor activity for analysis
ipdigger --enrich-abuseipdb --output-json /var/log/auth.log | jq '.statistics[] | select(.enrichment.isTor == "Yes")'
```

The `isTor` field in the output will show "Yes" for Tor exit nodes and "No" for regular IPs.

## Configuration

Create `~/.ipdigger/settings.conf` for API keys and caching:

```ini
[output]
default_json = false

[enrichment]
parallel_requests = 10
rdns_threads = 4

[performance]
parsing_threads = 0                   # 0 = auto-detect CPU cores (recommended)
chunk_size_mb = 10                    # Chunk size for parallel parsing (MB)

[cache]
enabled = true
cache_dir = ~/.ipdigger/cache
cache_ttl_hours = 24

[maxmind]
account_id = YOUR_ACCOUNT_ID          # Free account at maxmind.com
license_key = YOUR_LICENSE_KEY        # Required for GeoIP enrichment
db_dir = ~/.ipdigger/maxmind

[abuseipdb]
api_key = YOUR_API_KEY                # Free tier: 1000 requests/day at abuseipdb.com
```

### API Keys

**MaxMind GeoIP**: Free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup) - provides country, city, and ASN data

**AbuseIPDB**: Free tier (1000 requests/day) at [abuseipdb.com](https://www.abuseipdb.com/api) - provides abuse scores, reports, usage type, ISP, and Tor exit node detection

## Use Cases

**Security Analysis:**
```bash
# Find top attackers with threat intel
ipdigger --detect-login --enrich-abuseipdb --top-limit 20 --no-private /var/log/auth.log

# Identify Tor exit node activity
ipdigger --enrich-abuseipdb --detect-login /var/log/auth.log

# Filter and analyze non-EU attacks with Tor detection
ipdigger --geo-filter-none-eu --enrich-abuseipdb --detect-login --top-limit 10 /var/log/auth.log

# Check for expired TLS certificates
ipdigger --enrich-tls --top-limit 50 /var/log/nginx/access.log

# Discover misconfigured web servers (no CSP)
ipdigger --enrich-http --top-limit 20 /var/log/nginx/access.log
```

**Abuse Reporting:**
```bash
# Get abuse contacts for suspicious IPs
ipdigger --enrich-whois --detect-login --top-limit 10 /var/log/auth.log
```

**Log Analysis:**
```bash
# Find IPs associated with specific error messages
ipdigger --search "Failed password" /var/log/auth.log

# Search for multiple patterns using regex
ipdigger --search-regex "error|warning|critical" /var/log/nginx/error.log

# Combine search with geo-filtering and enrichment
ipdigger --search "Failed password" --geo-filter-none-eu --enrich-geo /var/log/auth.log

# Find specific attack patterns
ipdigger --search-regex "SQL injection|XSS|RCE" --enrich-abuseipdb --top-limit 20 /var/log/web.log
```

**Network Monitoring:**
```bash
# Check host availability and response times
ipdigger --enrich-ping --top-limit 20 /var/log/nginx/access.log

# Identify dead or unresponsive IPs
ipdigger --enrich-ping --detect-login /var/log/auth.log

# Combined network analysis with geo data
ipdigger --enrich-geo --enrich-ping --top-limit 10 /var/log/nginx/access.log
```

**Geographic Analysis:**
```bash
# Create interactive attack map
ipdigger --enrich-geo --output-geomap /var/log/auth.log > attack-map.geojson

# Map top 50 traffic sources
ipdigger --enrich-geo --top-limit 50 --output-geomap /var/log/nginx/access.log > traffic-map.geojson

# Focus on non-EU traffic for compliance analysis
ipdigger --geo-filter-none-eu --enrich-geo --top-limit 20 /var/log/nginx/access.log

# Identify traffic from outside GDPR regions
ipdigger --geo-filter-none-gdpr --detect-login --no-private /var/log/auth.log

# Export JSON for custom analysis
ipdigger --enrich-geo --output-json /var/log/nginx/access.log > traffic.json
```

**Time-Based Analysis:**
```bash
# Security incident investigation (specific window)
ipdigger --time-range "2024-01-13 14:30:00,2024-01-13 15:45:00" \
         --detect-login --enrich-abuseipdb /var/log/auth.log

# Last 24 hours with geo analysis
ipdigger --time-range ",24hours" --enrich-geo --top-limit 20 /var/log/auth.log

# Historical analysis (last week)
ipdigger --time-range "7days,1day" --enrich-geo --output-geomap /var/log/nginx/*.log > weekly.geojson

# Since specific event
ipdigger --time-range "2024-01-13 10:00:00," --detect-login /var/log/auth.log

# Recent failed logins (last hour)
ipdigger --time-range ",1hour" --detect-login --search "Failed" /var/log/auth.log

# Working hours analysis (9 AM to 5 PM on specific day)
ipdigger --time-range "2024-01-13 09:00:00,2024-01-13 17:00:00" /var/log/app.log
```

**Comprehensive Investigation:**
```bash
# Full enrichment for incident response
ipdigger --enrich-geo --enrich-rdns --enrich-whois --enrich-abuseipdb \
         --enrich-tls --enrich-http --detect-login \
         --output-json /var/log/auth.log > report.json

# Create comprehensive attack map with all enrichment
ipdigger --enrich-geo --enrich-abuseipdb --enrich-whois \
         --detect-login --output-geomap /var/log/auth.log > full-analysis.geojson
```

**Large File Processing:**
```bash
# Process 1GB+ files with auto-detected threading
ipdigger --top-limit 20 /var/log/huge-access.log

# Force single-threaded mode for debugging
ipdigger --single-threaded /var/log/huge-access.log

# Control thread count for optimal performance
ipdigger --threads 16 --enrich-geo /var/log/huge-access.log

# Process multiple large files in parallel
ipdigger "/var/log/archive/*.log"
```

## Development

```bash
make              # Build
make test         # Run tests
make clean        # Clean build artifacts
make deb          # Create Debian package
```

## License

MIT License - See LICENSE file for details

## Links

- **GitHub**: https://github.com/kawaiipantsu/ipdigger
- **Issues**: https://github.com/kawaiipantsu/ipdigger/issues
- **Releases**: https://github.com/kawaiipantsu/ipdigger/releases
- **Author**: kawaiipantsu @ [THUGSred Hacking Community](https://thugs.red)
