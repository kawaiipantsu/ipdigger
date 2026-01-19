#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <fstream>
#include "ipdigger.h"

void test_extract_ipv4() {
    std::cout << "Testing IPv4 extraction...\n";

    const auto& cache = ipdigger::get_regex_cache();

    auto ips = ipdigger::extract_ip_addresses("Connection from 192.168.1.1 port 22", cache);
    assert(ips.size() == 1);
    assert(ips[0] == "192.168.1.1");

    ips = ipdigger::extract_ip_addresses("10.0.0.1 connected to 10.0.0.2", cache);
    assert(ips.size() == 2);
    assert(ips[0] == "10.0.0.1");
    assert(ips[1] == "10.0.0.2");

    ips = ipdigger::extract_ip_addresses("No IP addresses here", cache);
    assert(ips.empty());

    ips = ipdigger::extract_ip_addresses("Edge cases: 255.255.255.255 and 0.0.0.0", cache);
    assert(ips.size() == 2);
    assert(ips[0] == "255.255.255.255");
    assert(ips[1] == "0.0.0.0");

    // Invalid IPs should not match
    ips = ipdigger::extract_ip_addresses("Invalid: 256.1.1.1 and 1.2.3.999", cache);
    assert(ips.empty());

    std::cout << "  ✓ All IPv4 extraction tests passed\n";
}

void test_extract_ipv6() {
    std::cout << "Testing IPv6 extraction...\n";

    const auto& cache = ipdigger::get_regex_cache();

    auto ips = ipdigger::extract_ip_addresses("IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", cache);
    assert(ips.size() == 1);
    assert(ips[0] == "2001:0db8:85a3:0000:0000:8a2e:0370:7334");

    ips = ipdigger::extract_ip_addresses("Compressed: ::1 and ::ffff:192.0.2.1", cache);
    assert(ips.size() >= 1);  // Should find at least one

    std::cout << "  ✓ All IPv6 extraction tests passed\n";
}

void test_extract_date() {
    std::cout << "Testing date extraction...\n";

    const auto& cache = ipdigger::get_regex_cache();
    time_t timestamp;

    // ISO 8601 format
    std::string date = ipdigger::extract_date("2024-01-13T12:34:56Z some log entry", timestamp, cache);
    assert(!date.empty());
    assert(date.find("2024") != std::string::npos);

    // Apache log format
    date = ipdigger::extract_date("[13/Jan/2024:12:34:56 +0000] GET /index.html", timestamp, cache);
    assert(!date.empty());

    // Syslog format
    date = ipdigger::extract_date("Jan 13 12:34:56 server sshd[1234]: message", timestamp, cache);
    assert(!date.empty());

    // Common format
    date = ipdigger::extract_date("2024-01-13 12:34:56 INFO: Application started", timestamp, cache);
    assert(!date.empty());

    // No date
    date = ipdigger::extract_date("No date in this line", timestamp, cache);
    assert(date.empty());
    assert(timestamp == 0);

    std::cout << "  ✓ All date extraction tests passed\n";
}

void test_parse_file() {
    std::cout << "Testing file parsing...\n";

    const auto& cache = ipdigger::get_regex_cache();

    // Create a test file
    std::string test_file = "test_log.txt";
    std::ofstream out(test_file);
    out << "2024-01-13 10:00:00 Connection from 192.168.1.100\n";
    out << "2024-01-13 10:05:00 Login from 10.0.0.50\n";
    out << "2024-01-13 10:10:00 Access from 192.168.1.100\n";
    out << "No IP address in this line\n";
    out << "2024-01-13 10:15:00 Multiple: 172.16.0.1 and 172.16.0.2\n";
    out.close();

    auto entries = ipdigger::parse_file(test_file, cache);

    assert(entries.size() == 5);  // 5 IP addresses total
    assert(entries[0].ip_address == "192.168.1.100");
    assert(entries[0].line_number == 1);
    assert(!entries[0].date_string.empty());

    // Clean up
    std::remove(test_file.c_str());

    std::cout << "  ✓ All file parsing tests passed\n";
}

void test_generate_statistics() {
    std::cout << "Testing statistics generation...\n";

    // Create test entries
    std::vector<ipdigger::IPEntry> entries;

    ipdigger::IPEntry e1;
    e1.ip_address = "192.168.1.1";
    e1.date_string = "2024-01-13 10:00:00";
    e1.timestamp = 1000;
    entries.push_back(e1);

    ipdigger::IPEntry e2;
    e2.ip_address = "192.168.1.1";
    e2.date_string = "2024-01-13 11:00:00";
    e2.timestamp = 2000;
    entries.push_back(e2);

    ipdigger::IPEntry e3;
    e3.ip_address = "10.0.0.1";
    e3.date_string = "2024-01-13 10:30:00";
    e3.timestamp = 1500;
    entries.push_back(e3);

    auto stats = ipdigger::generate_statistics(entries);

    assert(stats.size() == 2);  // Two unique IPs
    assert(stats["192.168.1.1"].count == 2);
    assert(stats["10.0.0.1"].count == 1);
    assert(stats["192.168.1.1"].first_timestamp == 1000);
    assert(stats["192.168.1.1"].last_timestamp == 2000);

    std::cout << "  ✓ All statistics generation tests passed\n";
}

void test_version() {
    std::cout << "Testing version...\n";

    std::string version = ipdigger::get_version();
    assert(!version.empty());

    std::cout << "  ✓ Version: " << version << "\n";
}

void test_parse_relative_time() {
    std::cout << "Testing relative time parsing...\n";

    time_t now = std::time(nullptr);

    // Test hours
    time_t result = ipdigger::parse_relative_time("24hours");
    assert(std::abs(result - (now - 86400)) < 2);

    result = ipdigger::parse_relative_time("1hour");
    assert(std::abs(result - (now - 3600)) < 2);

    // Test days
    result = ipdigger::parse_relative_time("7days");
    assert(std::abs(result - (now - 604800)) < 2);

    result = ipdigger::parse_relative_time("1day");
    assert(std::abs(result - (now - 86400)) < 2);

    // Test weeks
    result = ipdigger::parse_relative_time("1week");
    assert(std::abs(result - (now - 604800)) < 2);

    result = ipdigger::parse_relative_time("2weeks");
    assert(std::abs(result - (now - 1209600)) < 2);

    // Test short forms
    result = ipdigger::parse_relative_time("1h");
    assert(std::abs(result - (now - 3600)) < 2);

    result = ipdigger::parse_relative_time("30m");
    assert(std::abs(result - (now - 1800)) < 2);

    result = ipdigger::parse_relative_time("7d");
    assert(std::abs(result - (now - 604800)) < 2);

    std::cout << "  ✓ All relative time parsing tests passed\n";
}

void test_parse_time_string() {
    std::cout << "Testing time string parsing...\n";

    const auto& cache = ipdigger::get_regex_cache();

    // Unix timestamp
    time_t result = ipdigger::parse_time_string("1705136400", cache);
    assert(result == 1705136400);

    // ISO format with T separator
    result = ipdigger::parse_time_string("2024-01-13T12:34:56Z", cache);
    assert(result > 0);

    // Common format (space separator)
    result = ipdigger::parse_time_string("2024-01-13 12:34:56", cache);
    assert(result > 0);

    // Date only
    result = ipdigger::parse_time_string("2024-01-13", cache);
    assert(result > 0);

    // Relative time
    time_t now = std::time(nullptr);
    result = ipdigger::parse_time_string("1hour", cache);
    assert(std::abs(result - (now - 3600)) < 2);

    // Empty string (should return 0)
    result = ipdigger::parse_time_string("", cache);
    assert(result == 0);

    result = ipdigger::parse_time_string("   ", cache);
    assert(result == 0);

    std::cout << "  ✓ All time string parsing tests passed\n";
}

void test_time_range_parsing() {
    std::cout << "Testing time range parsing...\n";

    const auto& cache = ipdigger::get_regex_cache();

    // Both bounds with Unix timestamps
    ipdigger::TimeRange range = ipdigger::parse_time_range_arg("1705136400,1705222800", cache);
    assert(range.has_start && range.has_end);
    assert(range.start_time == 1705136400);
    assert(range.end_time == 1705222800);

    // Open start (last 24 hours)
    range = ipdigger::parse_time_range_arg(",24hours", cache);
    assert(!range.has_start && range.has_end);
    time_t now = std::time(nullptr);
    assert(std::abs(range.end_time - (now - 86400)) < 2);

    // Open end (since date)
    range = ipdigger::parse_time_range_arg("2024-01-13 00:00:00,", cache);
    assert(range.has_start && !range.has_end);
    assert(range.start_time > 0);

    // Both sides empty (no filtering)
    range = ipdigger::parse_time_range_arg(",", cache);
    assert(!range.has_start && !range.has_end);

    // Both sides with dates
    range = ipdigger::parse_time_range_arg("2024-01-13,2024-01-14", cache);
    assert(range.has_start && range.has_end);
    assert(range.end_time > range.start_time);

    // Relative times on both sides
    range = ipdigger::parse_time_range_arg("7days,1day", cache);
    assert(range.has_start && range.has_end);
    assert(range.end_time > range.start_time);

    std::cout << "  ✓ All time range parsing tests passed\n";
}

void test_time_range_contains() {
    std::cout << "Testing time range contains logic...\n";

    ipdigger::TimeRange range;
    range.start_time = 1000;
    range.end_time = 2000;
    range.has_start = true;
    range.has_end = true;

    // Test within range
    assert(range.contains(1500, false));

    // Test at boundaries
    assert(range.contains(1000, false));
    assert(range.contains(2000, false));

    // Test before range
    assert(!range.contains(500, false));

    // Test after range
    assert(!range.contains(2500, false));

    // Test no timestamp without include flag
    assert(!range.contains(0, false));

    // Test no timestamp with include flag
    assert(range.contains(0, true));

    // Test open start
    ipdigger::TimeRange open_start;
    open_start.end_time = 2000;
    open_start.has_end = true;
    open_start.has_start = false;
    assert(open_start.contains(500, false));
    assert(open_start.contains(1999, false));
    assert(!open_start.contains(2001, false));

    // Test open end
    ipdigger::TimeRange open_end;
    open_end.start_time = 1000;
    open_end.has_start = true;
    open_end.has_end = false;
    assert(!open_end.contains(500, false));
    assert(open_end.contains(1001, false));
    assert(open_end.contains(10000, false));

    // Test no bounds (should accept everything except 0 without flag)
    ipdigger::TimeRange no_bounds;
    assert(no_bounds.contains(500, false));
    assert(no_bounds.contains(5000000, false));
    assert(!no_bounds.contains(0, false));
    assert(no_bounds.contains(0, true));

    std::cout << "  ✓ All time range contains tests passed\n";
}

int main() {
    std::cout << "Running IPDigger tests...\n\n";

    try {
        test_extract_ipv4();
        test_extract_ipv6();
        test_extract_date();
        test_parse_file();
        test_generate_statistics();
        test_parse_relative_time();
        test_parse_time_string();
        test_time_range_parsing();
        test_time_range_contains();
        test_version();

        std::cout << "\n✓ All tests passed successfully!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}
