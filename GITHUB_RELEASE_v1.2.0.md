# IP Digger v1.2.0 - WHOIS, Login Detection & Threat Intelligence

## 🚀 Major Features

### 🔍 WHOIS Enrichment
Native WHOIS lookups with automatic referral following. Extract network ownership, abuse contacts, CIDR ranges, and admin details from all regional registries.

```bash
ipdigger --enrich-whois /var/log/auth.log
```

### 🔐 Login Detection
Intelligent authentication tracking with 35+ keyword patterns. Automatically identifies failed and successful login attempts.

```bash
ipdigger --detect-login /var/log/auth.log
```

### 🛡️ AbuseIPDB Integration
Real-time threat intelligence with confidence scores, usage types, and community reports.

```bash
ipdigger --enrich-abuseipdb /var/log/auth.log
```

### 🎚️ Smart Filtering
- `--no-private`: Exclude RFC 1918 and private IP ranges
- `--top-10/20/50/100`: Focus on most active IPs

## 📦 What's Included

**New Enrichment Options:**
- `--enrich-whois`: Network ownership & abuse contact information
- `--enrich-abuseipdb`: Threat intelligence & abuse scoring
- `--detect-login`: Authentication event tracking (success/failed)

**New Filtering:**
- `--no-private`: Remove private/local network addresses
- `--top-N`: Show only top N IPs by occurrence count

**Enhancements:**
- Progress bars with elapsed time for all enrichment operations
- MaxMind authentication now uses Account ID + License Key
- JSON output includes login statistics
- Optimized table columns (`country_code` → `cc`)

## 💡 Quick Examples

### Find Top Attackers
```bash
ipdigger --detect-login --enrich-whois --enrich-abuseipdb \
         --top-20 --no-private /var/log/auth.log
```

### Get Abuse Contacts
```bash
ipdigger --enrich-whois --detect-login --top-10 /var/log/auth.log
```

### Comprehensive Analysis
```bash
ipdigger --enrich-geo --enrich-rdns --enrich-whois --enrich-abuseipdb \
         --detect-login --output-json /var/log/auth.log > report.json
```

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

## 🔒 Security

Maintains all security hardening: PIE/ASLR, stack protection, full RELRO, non-executable stack, control flow protection.

## 📋 Requirements

- GCC 7+ or Clang 5+ with C++17 support
- libcurl4-openssl-dev, libssl-dev, libmaxminddb-dev, zlib1g-dev

## ✅ Checksums (SHA256)

```
87b1011ebf4cd1903a74b2fa972e2d8c96e579238712bd3ee4912973ebefaa51  ipdigger_1.2.0_amd64.deb
```

Full changelog: [CHANGELOG.md](CHANGELOG.md)
