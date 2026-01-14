# IPDigger v1.3.0 - Search Functionality Release

## New Features

✨ **Search Functionality**
- Added `--search <string>` flag for case-insensitive literal string search
- Added `--search-regex <pattern>` flag for case-insensitive regex pattern search
- New **SearchHits** column shows count of matching lines per IP
- Full integration with existing enrichment and filtering flags

## Enhancements

📊 **Enhanced Statistics Tracking**
- Search hit counts tracked per IP address
- Smart column display (SearchHits only shown when search is active)
- JSON output includes `search_hits` field when search is used

📝 **Documentation Updates**
- Comprehensive search feature documentation
- New usage examples and use cases
- Updated feature list and quick start guide

## Use Cases

**Log Analysis:**
```bash
# Find IPs associated with specific error messages
ipdigger --search "Failed password" /var/log/auth.log

# Search for multiple patterns using regex
ipdigger --search-regex "error|warning|critical" /var/log/nginx/error.log

# Combine with geo-filtering for targeted analysis
ipdigger --search "Failed password" --geo-filter-none-eu --enrich-geo /var/log/auth.log

# Find specific attack patterns
ipdigger --search-regex "SQL injection|XSS|RCE" --enrich-abuseipdb --top-20 /var/log/web.log
```

## Example Output

### ASCII Table
```
------------------------------------------------------------------------------------
| IP Address      | First Seen          | Last Seen           | Count | SearchHits |
------------------------------------------------------------------------------------
| 203.0.113.45    | 2024-01-13 10:02:00 | 2024-01-13 10:06:00 |     3 |          2 |
| 192.168.1.100   | 2024-01-13 10:00:00 | 2024-01-13 10:01:00 |     2 |          1 |
| 8.8.8.8         | 2024-01-13 10:04:00 | 2024-01-13 10:05:00 |     2 |          1 |
```

### JSON Output
```json
{
  "statistics": [
    {
      "ip_address": "203.0.113.45",
      "first_seen": "2024-01-13 10:02:00",
      "last_seen": "2024-01-13 10:06:00",
      "count": 3,
      "first_timestamp": 1705136520,
      "last_timestamp": 1705136760,
      "login_success_count": 0,
      "login_failed_count": 0,
      "search_hits": 2
    }
  ],
  "total": 3
}
```

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
git checkout v1.3.0
make
sudo make install
```

## What's Changed

### Core Changes
- Added `matches_search` field to IPEntry structure
- Added `search_hits` field to IPStats structure
- Enhanced `parse_file()` with regex compilation and literal string search
- Updated `generate_statistics()` to count search hits
- Modified `print_stats_table()` with conditional SearchHits column display
- Updated `print_stats_json()` with conditional search_hits field

### Files Modified
- `include/ipdigger.h` - Updated struct definitions and function signatures
- `src/ipdigger.cpp` - Implemented search logic and output formatting
- `src/main.cpp` - Added CLI flags and argument parsing
- `README.md` - Comprehensive documentation updates
- `Makefile` - Version bump to 1.3.0

### Documentation
- Added search feature section in README
- New usage examples and use cases
- Updated features list and quick start guide
- Enhanced help text with search flag descriptions

## Technical Details

**Search Behavior:**
- Case-insensitive matching for both literal and regex searches
- All IPs are included in output; SearchHits shows matching activity
- Count shows total lines per IP; SearchHits shows matching lines
- Invalid regex patterns are caught with descriptive error messages

**Performance:**
- Search is performed line-by-line during parsing
- Minimal performance impact on non-search operations
- Regex patterns compiled once and reused per file

## Requirements

- GCC 7+ or Clang 5+ (C++17)
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev

## Compatibility

- Works seamlessly with all existing flags:
  - `--enrich-geo`, `--enrich-rdns`, `--enrich-abuseipdb`, `--enrich-whois`, `--enrich-ping`
  - `--detect-login`
  - `--no-private`
  - `--geo-filter-none-eu`, `--geo-filter-none-gdpr`
  - `--top-10`, `--top-20`, `--top-50`, `--top-100`
  - `--output-json`

## Breaking Changes

None. This release is fully backward compatible with v1.2.0.

## Contributors

- kawaiipantsu @ THUGSred Hacking Community
- Co-Authored-By: Claude Sonnet 4.5

## Links

- **GitHub Repository**: https://github.com/kawaiipantsu/ipdigger
- **Release Page**: https://github.com/kawaiipantsu/ipdigger/releases/tag/v1.3.0
- **Issues**: https://github.com/kawaiipantsu/ipdigger/issues
- **Full Changelog**: https://github.com/kawaiipantsu/ipdigger/compare/v1.2.0...v1.3.0

---

**Released**: 2025-01-14
**Version**: 1.3.0
**Tag**: v1.3.0
