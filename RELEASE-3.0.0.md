# IPDigger v3.0.0 Release Notes

**Release Date:** 2026-01-27

## 🏗️ Major Feature: Multi-Architecture Support

This major release introduces **official multi-architecture Debian packages**, bringing IPDigger to three CPU architectures and expanding platform compatibility significantly.

### What's New

#### Three Official Architectures

IPDigger v3.0.0 now provides native packages for:

1. **AMD/Intel 64-bit (amd64)** - x86-64
   - Desktop computers, laptops, servers
   - Cloud instances (AWS, GCP, Azure, DigitalOcean, etc.)
   - Most common architecture
   - Package: `ipdigger_3.0.0_amd64.deb` (~228 KB)

2. **ARM 64-bit (arm64)** - aarch64
   - Raspberry Pi 3, 4, and 5
   - AWS Graviton instances
   - Apple Silicon (via Linux VM)
   - ARM-based cloud servers
   - IoT and edge devices
   - Package: `ipdigger_3.0.0_arm64.deb` (~199 KB)

3. **Intel 32-bit (i386)** - x86
   - Legacy systems
   - Older hardware
   - 32-bit Linux installations
   - Package: `ipdigger_3.0.0_i386.deb` (~249 KB)

#### Key Features

- **Native Performance**: Each architecture gets a properly compiled binary optimized for the target platform
- **Small Package Size**: All packages are stripped and dynamically linked (~200-250KB)
- **Cross-Compilation**: Built using GCC cross-compilers with full security hardening
- **Easy Build System**: New Makefile targets for building any architecture

### New Makefile Targets

```bash
# Build single architecture
make deb-amd64    # Build AMD/Intel 64-bit package
make deb-arm64    # Build ARM 64-bit package
make deb-i386     # Build Intel 32-bit package

# Build all architectures at once
make deb-all      # Produces all three .deb files

# Show help
make help         # Lists all available targets
```

### Installation

#### Choose Your Architecture

```bash
# Check your architecture
uname -m
# x86_64 = amd64
# aarch64 = arm64
# i686 or i386 = i386

# AMD/Intel 64-bit (most common)
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v3.0.0/ipdigger_3.0.0_amd64.deb
sudo dpkg -i ipdigger_3.0.0_amd64.deb

# ARM 64-bit (Raspberry Pi, AWS Graviton, etc.)
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v3.0.0/ipdigger_3.0.0_arm64.deb
sudo dpkg -i ipdigger_3.0.0_arm64.deb

# Intel 32-bit (legacy systems)
wget https://github.com/kawaiipantsu/ipdigger/releases/download/v3.0.0/ipdigger_3.0.0_i386.deb
sudo dpkg -i ipdigger_3.0.0_i386.deb
```

#### Verify Installation

```bash
# Check version and architecture
ipdigger --version

# Test basic functionality
echo "192.168.1.1" | ipdigger
```

### Technical Details

#### Build System Changes

- **Architecture Variables**: Introduced `ARCH` variable for cross-compilation control
- **Compiler Mapping**:
  - `amd64`: Native `g++` compiler
  - `arm64`: `aarch64-linux-gnu-g++` cross-compiler
  - `i386`: `i686-linux-gnu-g++` cross-compiler with `-m32` flag
- **Dynamic Linking**: All architectures use dynamic linking for smaller packages and simpler dependency management
- **Binary Stripping**: Architecture-specific strip tools minimize binary size

#### Security Hardening

All architectures maintain full security hardening:

- **Common to All**: Stack protection, PIE, format security, fortify source, stack clash protection, full RELRO, non-executable stack
- **x86/x64 Only**: Intel CET (Control-flow Enforcement Technology) protection flag
- **ARM64**: Excludes Intel-specific flags (architecture-appropriate hardening)

#### Package Metadata

Each package correctly identifies its architecture:

```bash
# Verify package architecture
dpkg-deb -I ipdigger_3.0.0_amd64.deb | grep Architecture
# Output: Architecture: amd64

dpkg-deb -I ipdigger_3.0.0_arm64.deb | grep Architecture
# Output: Architecture: arm64

dpkg-deb -I ipdigger_3.0.0_i386.deb | grep Architecture
# Output: Architecture: i386
```

### Use Cases

#### Raspberry Pi Log Analysis

Perfect for analyzing logs on Raspberry Pi devices:
```bash
# On Raspberry Pi 3/4/5 (ARM64)
sudo dpkg -i ipdigger_3.0.0_arm64.deb
ipdigger --enrich-geo /var/log/auth.log
```

#### AWS Graviton Instances

Optimized for ARM-based cloud computing:
```bash
# On AWS Graviton (ARM64)
ipdigger --stats --top-limit 20 /var/log/nginx/access.log.gz
```

#### Legacy Server Analysis

Support for older 32-bit systems:
```bash
# On 32-bit Linux servers
ipdigger --detect-login --enrich-threat /var/log/auth.log
```

#### Multi-Platform CI/CD

Build and test on all architectures:
```bash
# In CI/CD pipeline
make deb-all
# Produces packages for deployment across heterogeneous infrastructure
```

### Breaking Changes

**None.** This release is fully backward compatible. All existing features, flags, and functionality remain unchanged. The version bump to 3.0.0 reflects the significant expansion of platform support.

### Upgrading from 2.4.0

No breaking changes. Simply install the appropriate package for your architecture:

```bash
# Remove old version (optional)
sudo dpkg -r ipdigger

# Install new version for your architecture
sudo dpkg -i ipdigger_3.0.0_<arch>.deb

# Verify
ipdigger --version
```

### Dependencies

All architectures require the same runtime libraries:

- GCC 7+ or Clang 5+ (C++17)
- libcurl4-openssl-dev
- libssl-dev
- libmaxminddb-dev
- zlib1g-dev (for gzip compression)
- libbz2-dev (for bzip2 compression)
- liblzma-dev (for XZ compression)

### Building from Source

#### Native Build
```bash
git clone https://github.com/kawaiipantsu/ipdigger.git
cd ipdigger
git checkout v3.0.0
make
sudo make install
```

#### Cross-Compilation Setup

To build for other architectures, install cross-compilers:

```bash
# Add target architectures
sudo dpkg --add-architecture arm64
sudo dpkg --add-architecture i386
sudo apt-get update

# Install cross-compilers
sudo apt-get install -y g++-aarch64-linux-gnu g++-i686-linux-gnu

# Install dependencies for target architectures
sudo apt-get install -y \
    libcurl4-openssl-dev:arm64 libssl-dev:arm64 libmaxminddb-dev:arm64 \
    zlib1g-dev:arm64 libbz2-dev:arm64 liblzma-dev:arm64 \
    libcurl4-openssl-dev:i386 libssl-dev:i386 libmaxminddb-dev:i386 \
    zlib1g-dev:i386 libbz2-dev:i386 liblzma-dev:i386

# Build all architectures
make deb-all
```

### Package Checksums

SHA256 checksums for release packages:

```
c019518c6a3f5b5acc29860810d081f9bfb71715f7325605c9b507ed55a817ab  ipdigger_3.0.0_amd64.deb
a33ad838521709ee2e3fde7bb6c3ad308bfa6302d17a7bf9b4b99097e9721303  ipdigger_3.0.0_arm64.deb
5c06f02a1a300b7fd08b6883d381ac008c62fca057ea12f21c8b4f8f600235f0  ipdigger_3.0.0_i386.deb
```

Verify after download:
```bash
sha256sum -c ipdigger_3.0.0.checksums
```

### What's Next

Future releases will continue to support all three architectures. Consider:

- Testing IPDigger on your ARM devices
- Deploying to AWS Graviton for cost-effective log analysis
- Using on Raspberry Pi for edge security monitoring

### All Features Still Available

All features from v2.4.0 remain available on all architectures:

- ✅ IP Extraction (IPv4/IPv6)
- ✅ IP Correlation (users, hosts, custom patterns)
- ✅ GeoIP enrichment
- ✅ Threat intelligence (AbuseIPDB, THUGSred TI)
- ✅ WHOIS lookups
- ✅ Reverse DNS
- ✅ TLS/SSL inspection
- ✅ HTTP detection
- ✅ Login tracking
- ✅ Attack detection
- ✅ Time-range filtering
- ✅ Group-by analysis
- ✅ Search functionality
- ✅ Compressed file support (.gz, .bz2, .xz)
- ✅ Multi-threaded parsing
- ✅ JSON/GeoJSON output
- ✅ Statistics mode

### For More Information

- See `CHANGELOG.md` for full technical details
- Run `ipdigger --help` for complete feature list
- Visit https://github.com/kawaiipantsu/ipdigger for documentation

---

**Previous Release:** [2.4.0](RELEASE-2.4.0.md) - IP Correlation Feature

**Full Changelog:** [CHANGELOG.md](CHANGELOG.md)
