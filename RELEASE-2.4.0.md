# IPDigger v2.4.0 Release Notes

**Release Date:** 2026-01-19

## 🔗 New Feature: IP Correlation

This release introduces a powerful **IP Correlation** feature that maps IP addresses to other fields from structured log data. Perfect for security analysis, user tracking, and network mapping.

### What's New

#### Correlation Types

1. **User Correlation** (`--correlate-user <field>`)
   - Map IPs to username or email fields from CSV logs
   - Track which users accessed from which IP addresses
   - Identify shared credentials (multiple users from same IP)

2. **Host Correlation** (`--correlate-host <field>`)
   - Map IPs to hostname or domain fields
   - Optional domain extraction from FQDNs
   - Map IPs to infrastructure by hostname

3. **Custom Regex** (`--correlate-custom <regex>`)
   - Extract custom patterns using regex
   - Works on any text format (not just CSV)
   - Group by HTTP method, status code, or custom patterns

#### Key Features

- **Auto-Detection**: CSV format with comma, semicolon, pipe, or tab delimiters
- **Header Detection**: Automatically detects and uses header row
- **Quote Handling**: Properly handles quoted fields with embedded delimiters
- **Multiple Values**: IPs with multiple correlation values shown as comma-separated
- **Grouped Output**: Results grouped by correlation value, sorted by event count
- **JSON Support**: Full correlation data in JSON output
- **Domain Extraction**: Extracts root domain from FQDNs (mail.example.com → example.com)

#### New Help Command

- `--help-correlation`: Detailed correlation feature guide with examples and use cases

### Usage Examples

```bash
# Track which users accessed from which IPs
ipdigger --correlate-user username auth.csv

# Map IPs to domains with extraction
ipdigger --correlate-host fqdn --extract-domain dns.csv

# Group by HTTP method
ipdigger --correlate-custom 'method="(GET|POST)"' web.log

# Find shared credentials (JSON output)
ipdigger --correlate-user email --output-json login_audit.csv
```

### Sample Workflow

**Input CSV:**
```csv
timestamp,ip,user,action
2024-01-13 10:00:00,192.168.1.100,alice,login
2024-01-13 10:15:00,192.168.1.101,bob,login
2024-01-13 10:30:00,192.168.1.100,charlie,logout
```

**Command:**
```bash
ipdigger --correlate-user user login_audit.csv
```

**Output:**
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

### Technical Details

#### New Files
- `include/correlation.h` (90 lines) - Data structures and declarations
- `src/correlation.cpp` (450 lines) - Implementation

#### Modified Files
- `src/main.cpp` - CLI argument parsing and output dispatch
- `src/ipdigger.cpp` - Parse functions integration and statistics aggregation
- `include/ipdigger.h` - Function signature updates

#### Implementation Highlights
- **CSV Detection**: Analyzes first 20 lines for delimiter consistency (80% threshold)
- **State Machine Parser**: Proper quote handling with escaped quotes support
- **Domain Extraction**: Handles special TLDs (.co.uk, .com.au, etc.)
- **Field Mapping**: Dynamic field discovery from CSV header (case-insensitive)
- **Aggregation**: Collects and joins multiple correlation values per IP

### Limitations

- Only one correlation flag can be used at a time (mutually exclusive)
- CSV/delimited format required for `--correlate-user` and `--correlate-host`
- Custom regex (`--correlate-custom`) works on any text format
- Disables parallel parsing (uses single-threaded mode for sequential processing)
- Compatible with compressed files (.gz, .bz2, .xz)

### Installation

```bash
# From source
git clone https://github.com/kawaiipantsu/ipdigger.git
cd ipdigger
git checkout v2.4.0
make
sudo make install

# From Debian package
sudo dpkg -i ipdigger_2.4.0_amd64.deb
```

### Dependencies

- GCC 7+ or Clang 5+ (C++17)
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev (for gzip compression)
- libbz2-dev (for bzip2 compression)
- liblzma-dev (for XZ compression)

### Upgrading from 2.3.0

No breaking changes. All existing features and flags continue to work as expected. The new correlation flags are additive.

### For More Information

- Run `ipdigger --help-correlation` for detailed correlation guide
- See `CHANGELOG.md` for full technical details
- Visit https://github.com/kawaiipantsu/ipdigger for documentation

---

**Previous Release:** [2.3.0](RELEASE-2.3.0.md) - Compressed Files, Group-By, and THUGSred TI

**Full Changelog:** [CHANGELOG.md](CHANGELOG.md)
