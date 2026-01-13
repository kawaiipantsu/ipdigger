# Release Instructions for v1.2.0

## Files Ready for Release

1. **ipdigger_1.2.0_amd64.deb** (2.0 MB)
   - Debian package for installation

2. **ipdigger_1.2.0_checksums.txt** (170 bytes)
   - SHA256 checksums for verification

3. **RELEASE_NOTES_v1.2.0.md** (6.8 KB)
   - Comprehensive release notes with examples

4. **GITHUB_RELEASE_v1.2.0.md** (2.7 KB)
   - GitHub release description (copy-paste ready)

5. **CHANGELOG.md** (updated)
   - Full changelog with v1.2.0 section

## GitHub Release Steps

1. **Create Release on GitHub:**
   ```bash
   # Tag the release
   git tag -a v1.2.0 -m "Release v1.2.0 - WHOIS, Login Detection & Threat Intelligence"
   git push origin v1.2.0
   ```

2. **Create GitHub Release:**
   - Go to: https://github.com/kawaiipantsu/ipdigger/releases/new
   - Tag: `v1.2.0`
   - Title: `IP Digger v1.2.0 - WHOIS, Login Detection & Threat Intelligence`
   - Description: Copy contents from `GITHUB_RELEASE_v1.2.0.md`

3. **Upload Assets:**
   - ipdigger_1.2.0_amd64.deb
   - ipdigger_1.2.0_checksums.txt
   - RELEASE_NOTES_v1.2.0.md

4. **Mark as Latest Release:** ✅

## Version Information

- **Version:** 1.2.0
- **Release Date:** 2026-01-13
- **Previous Version:** 1.1.0

## Key Changes Summary

### Added
- WHOIS enrichment (--enrich-whois)
- Login detection (--detect-login)
- AbuseIPDB integration (--enrich-abuseipdb)
- Private IP filtering (--no-private)
- Top N filtering (--top-10/20/50/100)
- Progress bars with elapsed time

### Changed
- MaxMind now uses Account ID + License Key
- JSON output includes login statistics
- Column optimization (country_code → cc)

### Improved
- Modular per-provider enrichment
- Better user feedback with progress indicators

## Verification

Binary version check:
```bash
./bin/ipdigger --version
# Should show: IP Digger v1.2.0
```

Test suite:
```bash
make test
# All tests should pass
```

Package info:
```bash
dpkg-deb -I ipdigger_1.2.0_amd64.deb
```

## Checksums

SHA256:
```
87b1011ebf4cd1903a74b2fa972e2d8c96e579238712bd3ee4912973ebefaa51  ipdigger_1.2.0_amd64.deb
d73c85207165e8427e2c0f9b4e8c86a4c6074a335fa63b98fba59ec72c528a67  bin/ipdigger
```

## Post-Release

- Announce on relevant channels
- Update documentation if hosted separately
- Monitor for issues/feedback
- Consider social media announcement

---

All release artifacts have been generated and verified.
Ready for GitHub release creation!
