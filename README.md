# IPDigger

```
     ___________ ____________
    |           )._______.-'
    `----------'

       IP Digger v1.3.0
  Your swiss armyknife tool for IP addresses

         by kawaiipantsu
    THUGSred Hacking Community
       https://thugs.red
```

A secure C++ log analysis tool for extracting and enriching IP addresses from log files.

## Features

- 🔍 **IP Extraction**: IPv4 and IPv6 from any log format
- 📊 **Statistics**: Count, first/last seen per IP
- 🔎 **Search**: Filter logs by literal strings or regex patterns with hit counts per IP
- 🌍 **GeoIP**: MaxMind country/city/ASN data
- 🔐 **Login Detection**: Track authentication success/failures
- 🛡️ **Threat Intel**: AbuseIPDB abuse scoring & Tor exit node detection
- 📋 **WHOIS**: Network ownership and abuse contacts
- 🌐 **Reverse DNS**: Hostname resolution
- 🏓 **Ping Detection**: Response time measurement and host availability
- 🎯 **Filtering**: Private IPs, top N IPs, geographic filtering (EU/GDPR regions)
- 📦 **Formats**: ASCII tables or JSON output
- 🔒 **Secure**: Full security hardening (PIE, RELRO, stack protection)

## Installation

### Debian/Ubuntu
```bash
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v1.3.0/ipdigger_1.3.0_amd64.deb
sudo dpkg -i ipdigger_1.3.0_amd64.deb
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
- zlib1g-dev

## Quick Start

```bash
# Basic usage
ipdigger /var/log/nginx/access.log

# Multiple files
ipdigger "/var/log/*.log"

# With enrichment
ipdigger --enrich-geo --enrich-whois /var/log/auth.log

# Find top attackers
ipdigger --detect-login --top-20 --no-private /var/log/auth.log

# Geographic filtering (non-EU traffic)
ipdigger --geo-filter-none-eu /var/log/auth.log

# Check host availability
ipdigger --enrich-ping --top-10 /var/log/nginx/access.log

# Search for specific patterns
ipdigger --search "Failed password" /var/log/auth.log

# Full analysis
ipdigger --enrich-geo --enrich-whois --enrich-abuseipdb \
         --detect-login --top-10 --output-json /var/log/auth.log
```

## Usage

```
Usage: ipdigger [OPTIONS] <filename>

Options:
  --output-json      Output in JSON format

Enrichment:
  --enrich-geo       Enrich with geolocation data (MaxMind)
  --enrich-rdns      Enrich with reverse DNS lookups
  --enrich-abuseipdb Enrich with AbuseIPDB threat intelligence
  --enrich-whois     Enrich with WHOIS data (netname, abuse, CIDR, admin)
  --enrich-ping      Enrich with ping response time and availability

Analysis:
  --detect-login     Detect and track login attempts (success/failed)
  --search <string>  Filter lines by literal string and count hits per IP
  --search-regex <pattern> Filter lines by regex pattern and count hits per IP

Filtering:
  --no-private           Exclude private/local network addresses
  --geo-filter-none-eu   Filter to show only IPs outside the EU (auto-enables --enrich-geo)
  --geo-filter-none-gdpr Filter to show only IPs outside GDPR regions (auto-enables --enrich-geo)
  --top-10               Show only top 10 IPs by count
  --top-20               Show only top 20 IPs by count
  --top-50               Show only top 50 IPs by count
  --top-100              Show only top 100 IPs by count

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
ipdigger --enrich-geo --enrich-abuseipdb --top-10 /var/log/auth.log
```
```
| IP Address   | Country | City      | abuseScore | totalReports | isTor |
|-------------|---------|-----------|-----------|-------------|-------|
| 45.67.89.12 | CN      | Shanghai  | 95        | 247         | No    |
| 23.45.67.89 | RU      | Moscow    | 87        | 156         | Yes   |
```

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
ipdigger --detect-login --enrich-abuseipdb --top-20 --no-private /var/log/auth.log

# Identify Tor exit node activity
ipdigger --enrich-abuseipdb --detect-login /var/log/auth.log

# Filter and analyze non-EU attacks with Tor detection
ipdigger --geo-filter-none-eu --enrich-abuseipdb --detect-login --top-10 /var/log/auth.log
```

**Abuse Reporting:**
```bash
# Get abuse contacts for suspicious IPs
ipdigger --enrich-whois --detect-login --top-10 /var/log/auth.log
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
ipdigger --search-regex "SQL injection|XSS|RCE" --enrich-abuseipdb --top-20 /var/log/web.log
```

**Network Monitoring:**
```bash
# Check host availability and response times
ipdigger --enrich-ping --top-20 /var/log/nginx/access.log

# Identify dead or unresponsive IPs
ipdigger --enrich-ping --detect-login /var/log/auth.log

# Combined network analysis with geo data
ipdigger --enrich-geo --enrich-ping --top-10 /var/log/nginx/access.log
```

**Geographic Analysis:**
```bash
# Map traffic sources
ipdigger --enrich-geo --output-json /var/log/nginx/access.log > traffic.json

# Focus on non-EU traffic for compliance analysis
ipdigger --geo-filter-none-eu --enrich-geo --top-20 /var/log/nginx/access.log

# Identify traffic from outside GDPR regions
ipdigger --geo-filter-none-gdpr --detect-login --no-private /var/log/auth.log
```

**Comprehensive Investigation:**
```bash
# Full enrichment for incident response
ipdigger --enrich-geo --enrich-rdns --enrich-whois --enrich-abuseipdb \
         --detect-login --output-json /var/log/auth.log > report.json
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
