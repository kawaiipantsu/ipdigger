#!/bin/bash
# Script to create compressed test files for testing compression support

# Create test log file with sample data
cat > tests/test_compressed.log << 'EOF'
2024-01-19 10:00:00 192.168.1.1 GET /index.html
2024-01-19 10:01:00 203.0.113.5 POST /api/data
2024-01-19 10:02:00 2001:db8::1 GET /test
2024-01-19 10:03:00 198.51.100.42 Failed password for invalid user admin
2024-01-19 10:04:00 192.168.1.1 Accepted password for user john
2024-01-19 10:05:00 203.0.113.5 Failed password for invalid user root
2024-01-19 10:06:00 10.0.0.1 GET /admin/login
2024-01-19 10:07:00 172.16.0.5 POST /api/upload
2024-01-19 10:08:00 192.168.1.100 Connection closed by authenticating user admin
2024-01-19 10:09:00 198.51.100.42 Failed password for user admin from 198.51.100.42 port 54321 ssh2
EOF

# Create compressed versions
echo "Creating compressed test files..."

# Gzip
if command -v gzip &> /dev/null; then
    gzip -c tests/test_compressed.log > tests/test_compressed.log.gz
    echo "Created tests/test_compressed.log.gz"
else
    echo "Warning: gzip not found, skipping .gz file creation"
fi

# Bzip2
if command -v bzip2 &> /dev/null; then
    bzip2 -c tests/test_compressed.log > tests/test_compressed.log.bz2
    echo "Created tests/test_compressed.log.bz2"
else
    echo "Warning: bzip2 not found, skipping .bz2 file creation"
fi

# XZ
if command -v xz &> /dev/null; then
    xz -c tests/test_compressed.log > tests/test_compressed.log.xz
    echo "Created tests/test_compressed.log.xz"
else
    echo "Warning: xz not found, skipping .xz file creation"
fi

echo "Test files created successfully!"
