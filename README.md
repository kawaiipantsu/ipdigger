# IPDigger

```
     ___________ ____________
    |           )._______.-'
    `----------'

       IP Digger v1.2.0
  Your swiss armyknife tool for IP addresses

         by kawaiipantsu
    THUGSred Hacking Community
       https://thugs.red
```

A secure C++ log analysis tool for extracting and enriching IP addresses from log files.

## Features

- 🔍 **IP Extraction**: IPv4 and IPv6 from any log format
- 📊 **Statistics**: Count, first/last seen per IP
- 🌍 **GeoIP**: MaxMind country/city/ASN data
- 🔐 **Login Detection**: Track authentication success/failures
- 🛡️ **Threat Intel**: AbuseIPDB abuse scoring
- 📋 **WHOIS**: Network ownership and abuse contacts
- 🌐 **Reverse DNS**: Hostname resolution
- 🎯 **Filtering**: Private IPs, top N IPs
- 📦 **Formats**: ASCII tables or JSON output
- 🔒 **Secure**: Full security hardening (PIE, RELRO, stack protection)

## Installation

### Debian/Ubuntu
```bash
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v1.2.0/ipdigger_1.2.0_amd64.deb
sudo dpkg -i ipdigger_1.2.0_amd64.deb
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

Analysis:
  --detect-login     Detect and track login attempts (success/failed)

Filtering:
  --no-private       Exclude private/local network addresses
  --top-10           Show only top 10 IPs by count
  --top-20           Show only top 20 IPs by count
  --top-50           Show only top 50 IPs by count
  --top-100          Show only top 100 IPs by count

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
| IP Address   | Country | City      | abuseScore | totalReports |
|-------------|---------|-----------|-----------|-------------|
| 45.67.89.12 | CN      | Shanghai  | 95        | 247         |
| 23.45.67.89 | RU      | Moscow    | 87        | 156         |
```

### JSON Output
```bash
ipdigger --enrich-whois --output-json /var/log/auth.log
```
```json
{
  "statistics": [
    {
      "ip_address": "8.8.8.8",
      "first_seen": "2024-01-13 10:00:00",
      "last_seen": "2024-01-13 10:03:00",
      "count": 2,
      "first_timestamp": 1705136400,
      "last_timestamp": 1705136580,
      "login_success_count": 2,
      "login_failed_count": 0,
      "enrichment": {
        "netname": "GOGL",
        "abuse": "network-abuse@google.com",
        "cidr": "8.8.8.0 - 8.8.8.255"
      }
    }
  ],
  "total": 1
}
```

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
account_id = YOUR_ACCOUNT_ID
license_key = YOUR_LICENSE_KEY
db_dir = ~/.ipdigger/maxmind

[abuseipdb]
api_key = YOUR_API_KEY
```

## Use Cases

**Security Analysis:**
```bash
# Find top attackers with threat intel
ipdigger --detect-login --enrich-abuseipdb --top-20 --no-private /var/log/auth.log
```

**Abuse Reporting:**
```bash
# Get abuse contacts for suspicious IPs
ipdigger --enrich-whois --detect-login --top-10 /var/log/auth.log
```

**Geographic Analysis:**
```bash
# Map traffic sources
ipdigger --enrich-geo --output-json /var/log/nginx/access.log > traffic.json
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
