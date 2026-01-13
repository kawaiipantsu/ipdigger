# IPDigger v1.1.0 - IP Enrichment Release

## What's New

This release introduces a powerful **IP enrichment system** that transforms IPDigger from a simple log parser into a comprehensive IP intelligence tool.

### Key Features

- **GeoIP Lookups**: Identify country, city, and ASN using MaxMindDB
- **Threat Intelligence**: Detect potentially malicious IP addresses
- **Reverse DNS**: Resolve IPs to hostnames automatically
- **Smart Caching**: 24-hour cache with configurable TTL
- **Configuration System**: Flexible settings at `~/.ipdigger/settings.conf`
- **Parallel Processing**: Fast enrichment with concurrent requests

### Installation

**Debian/Ubuntu:**
```bash
wget https://github.com/yourusername/ipdigger/releases/download/v1.1.0/ipdigger_1.1.0_amd64.deb
sudo apt-get install libcurl4 libssl3 libmaxminddb0
sudo dpkg -i ipdigger_1.1.0_amd64.deb
```

**From Source:**
```bash
git clone https://github.com/yourusername/ipdigger.git
cd ipdigger
git checkout v1.1.0
make
sudo make install
```

### Quick Start

```bash
# Enable enrichment for comprehensive IP intelligence
ipdigger --enrich /var/log/nginx/access.log

# Show statistics with enrichment data
ipdigger --enrich --stats /var/log/auth.log

# JSON output with all enrichment fields
ipdigger --enrich --output-json /var/log/access.log
```

## Upgrade Notes

Fully backward compatible with v1.0.0. All existing commands work unchanged. New enrichment features are opt-in via `--enrich` flag.

## Checksums

**SHA256:** `eee85ee82d532d2f1f32afb8aec937e5d18f169da1a85d5c124acdf8e5420c74`

Verify:
```bash
sha256sum ipdigger_1.1.0_amd64.deb
```

## What's Changed Since v1.0.0

**Added:**
- IP enrichment system (GeoIP, threat intel, rDNS)
- Configuration file support
- Intelligent caching system
- MaxMindDB integration
- Multi-threaded processing

**Dependencies:**
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev

See [CHANGELOG.md](CHANGELOG.md) for complete details.

## Links

- [Full Release Notes](RELEASE_NOTES_v1.1.0.md)
- [Changelog](CHANGELOG.md)
- [Documentation](README.md)
- [Report Issues](https://github.com/yourusername/ipdigger/issues)
