# IPDigger

A secure C++ log analysis tool that extracts IP addresses and timestamps from log files, presenting them in clean ASCII tables.

## Features

- **IP Address Extraction**: Automatically detects and extracts both IPv4 and IPv6 addresses
- **Glob Pattern Support**: Process multiple files using wildcards (`*.log`, `/var/log/*.log`)
- **Date/Timestamp Parsing**: Supports multiple common log formats:
  - ISO 8601 / RFC3339: `2024-01-13T12:34:56Z`
  - Apache/Nginx logs: `[13/Jan/2024:12:34:56 +0000]`
  - Syslog format: `Jan 13 12:34:56`
  - Common format: `2024-01-13 12:34:56`
- **ASCII Table Output**: Clean, formatted tables for easy reading
- **JSON Output**: Machine-readable JSON format for automation
- **Statistical Analysis**: Show first seen, last seen, and occurrence count per IP
- **Security Hardened**: Compiled with modern C++ security flags

## Quick Start

### Build
```bash
make
```

### Basic Usage
```bash
# Single file
./bin/ipdigger /var/log/nginx/access.log

# Multiple files with wildcards
./bin/ipdigger "/var/log/*.log"
./bin/ipdigger /var/log/nginx/*.log
```

### Show Statistics
```bash
./bin/ipdigger --stats /var/log/auth.log
./bin/ipdigger --stats "/var/log/*.log"
```

## Installation

### Install System-wide
```bash
sudo make install
```

This installs `ipdigger` to `/usr/local/bin`.

### Create Debian Package
```bash
make deb
sudo dpkg -i ipdigger_1.0.0_amd64.deb
```

### Uninstall
```bash
sudo make uninstall
# or if installed via deb:
sudo dpkg -r ipdigger
```

## Usage Examples

### Normal Mode
Shows unique IP addresses (first occurrence) with their line numbers and timestamps:

```bash
$ ipdigger sample.log
-------------------------------------------------------------------------
| Line | IP Address                              | Date/Time            |
-------------------------------------------------------------------------
|    1 | 192.168.1.100                           | 2024-01-13 08:15:23  |
|    2 | 10.0.0.50                               | 2024-01-13 08:16:45  |
|    3 | 203.0.113.45                            | 2024-01-13 08:17:12  |
-------------------------------------------------------------------------
Total: 3 unique IP address(es) found
```

### Statistics Mode
Shows aggregated statistics for each unique IP address:

```bash
$ ipdigger --stats sample.log
------------------------------------------------------------------------------------------------
| IP Address                              | First Seen           | Last Seen           | Count |
------------------------------------------------------------------------------------------------
| 192.168.1.100                           | 2024-01-13 08:15:23  | 2024-01-13 08:25:30 |     4 |
| 10.0.0.50                               | 2024-01-13 08:16:45  | 2024-01-13T08:22:00 |     2 |
| 203.0.113.45                            | 2024-01-13 08:17:12  | 2024-01-13 08:17:12 |     1 |
------------------------------------------------------------------------------------------------
Total: 3 unique IP address(es)
```

### JSON Output
Both normal and statistics modes can output in JSON format:

```bash
$ ipdigger --output-json sample.log
{
  "ip_addresses": [
    {
      "ip_address": "192.168.1.100",
      "line_number": 1,
      "date": "2024-01-13 08:15:23",
      "timestamp": 1705130123
    },
    {
      "ip_address": "10.0.0.50",
      "line_number": 2,
      "date": "2024-01-13 08:16:45",
      "timestamp": 1705130205
    }
  ],
  "total": 2
}

$ ipdigger --stats --output-json sample.log
{
  "statistics": [
    {
      "ip_address": "192.168.1.100",
      "first_seen": "2024-01-13 08:15:23",
      "last_seen": "2024-01-13 08:25:30",
      "count": 4,
      "first_timestamp": 1705130123,
      "last_timestamp": 1705130730
    }
  ],
  "total": 1
}
```

## Command Line Options

```
Usage: ipdigger [OPTIONS] <filename>

Options:
  --stats        Show statistical summary (first seen, last seen, count)
  --output-json  Output in JSON format
  --help         Display help message
  --version      Display version information

Examples:
  ipdigger /var/log/nginx/access.log
  ipdigger --stats /var/log/auth.log
  ipdigger "/var/log/*.log"
  ipdigger --output-json "/var/log/*.log"
  ipdigger --stats --output-json "/var/log/nginx/*.log"

Note: Quote glob patterns to prevent shell expansion
```

## Security Features

IPDigger is compiled with comprehensive security hardening:

- **Stack Protection**: `-fstack-protector-strong`, `-fstack-clash-protection`
- **Position Independent Executable**: `-fPIE`, `-pie`
- **Fortify Source**: `-D_FORTIFY_SOURCE=2`
- **Full RELRO**: `-z,relro,-z,now` (all relocations read-only at startup)
- **Non-executable Stack**: `-z,noexecstack`
- **Control Flow Protection**: `-fcf-protection`
- **Format String Protection**: `-Wformat -Wformat-security`
- **Strict Warnings**: All warnings treated as errors

## Requirements

- GCC 7+ or Clang 5+ (with C++17 support)
- Make
- dpkg-deb (for Debian package creation)

## Project Structure

```
.
├── Makefile           # Build system with security flags
├── include/           # Header files
│   └── ipdigger.h
├── src/               # Source files
│   ├── main.cpp       # CLI interface
│   └── ipdigger.cpp   # Core functionality
├── tests/             # Test suite
│   └── test_main.cpp
└── sample.log         # Example log file
```

## Development

### Build Commands
```bash
make              # Build project
make test         # Run test suite
make clean        # Remove build artifacts
make help         # Show all targets
make debug        # Show build configuration
```

### Running Tests
```bash
make test
```

The test suite validates:
- IPv4 and IPv6 address extraction
- Date/timestamp parsing across multiple formats
- File parsing and entry creation
- Statistical aggregation
- Table formatting

## Supported Log Formats

IPDigger automatically detects and parses various log formats:

- **Nginx/Apache Access Logs**: `[13/Jan/2024:12:34:56 +0000] 192.168.1.1 GET /`
- **Syslog**: `Jan 13 12:34:56 server sshd[1234]: Connection from 192.168.1.1`
- **Application Logs**: `2024-01-13 12:34:56 INFO: Request from 192.168.1.1`
- **ISO 8601**: `2024-01-13T12:34:56Z API call from 192.168.1.1`

## Use Cases

- **Security Analysis**: Identify suspicious IP addresses across multiple log files
- **Traffic Analysis**: See which IPs access your services most frequently
- **Intrusion Detection**: Track failed login attempts by IP across all servers
- **Log Parsing**: Extract structured data from unstructured logs
- **Compliance**: Generate reports of access patterns
- **Multi-Server Analysis**: Process logs from multiple servers using wildcards
- **Automated Monitoring**: Use JSON output for integration with monitoring tools

## License

[Add your license here]

## Contributing

Contributions welcome! Please ensure:
- Code follows C++ Core Guidelines
- All tests pass (`make test`)
- Security flags remain enabled
- New features include tests
