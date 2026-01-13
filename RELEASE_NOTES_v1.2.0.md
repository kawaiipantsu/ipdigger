# IP Digger v1.2.0 Release Notes

Release Date: 2026-01-13

## Overview

IP Digger v1.2.0 is a major feature release that adds comprehensive WHOIS enrichment, intelligent login detection, threat intelligence via AbuseIPDB, and powerful filtering options. This release significantly enhances IP analysis capabilities for security professionals and system administrators.

## 🎯 Highlights

### 🔍 WHOIS Enrichment (`--enrich-whois`)
Native WHOIS lookups with automatic referral following across all regional registries. Extract network ownership information, abuse contacts, CIDR ranges, and administrative details directly from authoritative sources.

### 🔐 Login Detection (`--detect-login`)
Intelligent authentication event tracking that automatically identifies failed and successful login attempts across various log formats using 35+ keyword patterns.

### 🛡️ AbuseIPDB Threat Intelligence (`--enrich-abuseipdb`)
Integrate real-time threat intelligence to identify malicious IPs with confidence scores, usage types, report counts, and ISP information.

### 🎚️ Filtering & Focus Tools
New filtering options to exclude private networks (`--no-private`) and focus on top attackers (`--top-10/20/50/100`).

---

## 📦 What's New

### WHOIS Enrichment
```bash
ipdigger --enrich-whois /var/log/auth.log
```

**Features:**
- ✅ Automatic referral following (IANA → RIRs)
- ✅ Queries 6 regional registries (IANA, ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- ✅ Extracts: netname, abuse email, CIDR range, admin contact
- ✅ 1-second rate limiting for respectful querying
- ✅ Progress bar with elapsed time

**Example Output:**
```
| IP Address   | netname    | abuse                    | cidr                |
|-------------|------------|--------------------------|---------------------|
| 8.8.8.8     | GOGL       | network-abuse@google.com | 8.8.8.0 - 8.8.8.255 |
```

### Login Detection
```bash
ipdigger --detect-login /var/log/auth.log
```

**Features:**
- ✅ Detects 35+ failure keywords (failed, denied, blocked, wrong password, etc.)
- ✅ Aggregates success/failure counts per IP
- ✅ Works with SSH, FTP, web auth, and other log formats
- ✅ Compact display format: `OK:2 F:5` (2 successes, 5 failures)

**Example Output:**
```
| IP Address      | Count | Login        |
|----------------|-------|-------------|
| 203.0.113.45   |     8 | OK:0 F:8    |
| 192.0.2.100    |     3 | OK:3 F:0    |
```

### AbuseIPDB Threat Intelligence
```bash
ipdigger --enrich-abuseipdb /var/log/auth.log
```

**Features:**
- ✅ Abuse confidence score (0-100 risk rating)
- ✅ Usage type (Data Center, ISP, Hosting, etc.)
- ✅ Total community reports count
- ✅ ISP information
- ✅ 100ms rate limiting for API compliance
- ✅ Progress tracking

**Example Output:**
```
| IP Address   | abuseScore | usageType   | totalReports | isp          |
|-------------|-----------|-------------|-------------|--------------|
| 45.67.89.12 | 95        | Data Center | 247         | Hostile ISP  |
```

### Private IP Filtering
```bash
ipdigger --no-private /var/log/nginx/access.log
```

**Filters out:**
- RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8)
- Link-local (169.254.0.0/16)
- IPv6 private ranges (fc00::/7, fe80::/10)

### Top N Filtering
```bash
ipdigger --top-10 /var/log/auth.log
ipdigger --top-20 --enrich-whois /var/log/nginx/access.log
```

**Options:**
- `--top-10`: Show top 10 IPs by count
- `--top-20`: Show top 20 IPs by count
- `--top-50`: Show top 50 IPs by count
- `--top-100`: Show top 100 IPs by count

### Enhanced Progress Indicators

All enrichment operations now show real-time progress:
```
Enriching [============================>                ] 142/250 (56%) 18s
```

Format: `[progress bar] completed/total (percentage) elapsed_seconds`

---

## 🔄 Changes

### MaxMind Authentication Update
- **Old:** Single license key
- **New:** Account ID + License Key (HTTP Basic Auth)
- **Config:**
  ```ini
  [maxmind]
  account_id = YOUR_ACCOUNT_ID
  license_key = YOUR_LICENSE_KEY
  ```

### JSON Output Enhancement
New fields in JSON output:
```json
{
  "login_success_count": 2,
  "login_failed_count": 8
}
```

### Column Optimization
- Renamed `country_code` → `cc` for better table formatting

### Configuration Cleanup
- Removed generic `--enrich` flag
- Each provider now has dedicated flag: `--enrich-geo`, `--enrich-rdns`, `--enrich-abuseipdb`, `--enrich-whois`
- Can combine multiple: `--enrich-geo --enrich-whois --enrich-abuseipdb`

---

## 💡 Usage Examples

### Security Analysis
Find top attackers with full intelligence:
```bash
ipdigger --detect-login --enrich-whois --enrich-abuseipdb \
         --top-20 --no-private /var/log/auth.log
```

### Network Reconnaissance
Identify external IPs with geographic and network data:
```bash
ipdigger --enrich-geo --enrich-whois --no-private \
         --output-json /var/log/nginx/access.log > results.json
```

### Abuse Reporting
Get abuse contacts for suspicious IPs:
```bash
ipdigger --enrich-whois --detect-login \
         --top-10 /var/log/auth.log
```

### Threat Intelligence
Combine all enrichment sources for comprehensive analysis:
```bash
ipdigger --enrich-geo --enrich-rdns --enrich-whois --enrich-abuseipdb \
         --detect-login --top-50 /var/log/auth.log
```

---

## 📥 Installation

### Debian/Ubuntu
```bash
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v1.2.0/ipdigger_1.2.0_amd64.deb
sudo dpkg -i ipdigger_1.2.0_amd64.deb
```

### From Source
```bash
git clone https://github.com/kawaiipantsu/ipdigger.git
cd ipdigger
git checkout v1.2.0
make
sudo make install
```

---

## 🔐 Security

This release maintains all security hardening features:
- Stack protection (canaries, clash protection)
- Position Independent Executable (PIE) with ASLR
- Full RELRO (read-only relocations)
- Non-executable stack
- Control flow protection
- Format string protection
- Fortified source functions

---

## 📋 Requirements

- GCC 7+ or Clang 5+ with C++17 support
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev
- GNU Make

---

## 🐛 Bug Reports

Report issues at: https://github.com/kawaiipantsu/ipdigger/issues

---

## 📄 Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

---

## ✅ Checksums

### SHA256
```
87b1011ebf4cd1903a74b2fa972e2d8c96e579238712bd3ee4912973ebefaa51  ipdigger_1.2.0_amd64.deb
d73c85207165e8427e2c0f9b4e8c86a4c6074a335fa63b98fba59ec72c528a67  ipdigger (binary)
```

Verify:
```bash
sha256sum -c ipdigger_1.2.0_checksums.txt
```

---

## 🙏 Acknowledgments

Thanks to all users who provided feedback and feature requests. Special thanks to the open-source community for the excellent libraries we depend on: libcurl, OpenSSL, MaxMindDB, and nlohmann/json.

---

## 📜 License

IP Digger is released under the MIT License. See LICENSE file for details.
