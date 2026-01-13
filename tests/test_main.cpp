#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <fstream>
#include "ipdigger.h"

void test_extract_ipv4() {
    std::cout << "Testing IPv4 extraction...\n";

    auto ips = ipdigger::extract_ip_addresses("Connection from 192.168.1.1 port 22");
    assert(ips.size() == 1);
    assert(ips[0] == "192.168.1.1");

    ips = ipdigger::extract_ip_addresses("10.0.0.1 connected to 10.0.0.2");
    assert(ips.size() == 2);
    assert(ips[0] == "10.0.0.1");
    assert(ips[1] == "10.0.0.2");

    ips = ipdigger::extract_ip_addresses("No IP addresses here");
    assert(ips.empty());

    ips = ipdigger::extract_ip_addresses("Edge cases: 255.255.255.255 and 0.0.0.0");
    assert(ips.size() == 2);
    assert(ips[0] == "255.255.255.255");
    assert(ips[1] == "0.0.0.0");

    // Invalid IPs should not match
    ips = ipdigger::extract_ip_addresses("Invalid: 256.1.1.1 and 1.2.3.999");
    assert(ips.empty());

    std::cout << "  ✓ All IPv4 extraction tests passed\n";
}

void test_extract_ipv6() {
    std::cout << "Testing IPv6 extraction...\n";

    auto ips = ipdigger::extract_ip_addresses("IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert(ips.size() == 1);
    assert(ips[0] == "2001:0db8:85a3:0000:0000:8a2e:0370:7334");

    ips = ipdigger::extract_ip_addresses("Compressed: ::1 and ::ffff:192.0.2.1");
    assert(ips.size() >= 1);  // Should find at least one

    std::cout << "  ✓ All IPv6 extraction tests passed\n";
}

void test_extract_date() {
    std::cout << "Testing date extraction...\n";

    time_t timestamp;

    // ISO 8601 format
    std::string date = ipdigger::extract_date("2024-01-13T12:34:56Z some log entry", timestamp);
    assert(!date.empty());
    assert(date.find("2024") != std::string::npos);

    // Apache log format
    date = ipdigger::extract_date("[13/Jan/2024:12:34:56 +0000] GET /index.html", timestamp);
    assert(!date.empty());

    // Syslog format
    date = ipdigger::extract_date("Jan 13 12:34:56 server sshd[1234]: message", timestamp);
    assert(!date.empty());

    // Common format
    date = ipdigger::extract_date("2024-01-13 12:34:56 INFO: Application started", timestamp);
    assert(!date.empty());

    // No date
    date = ipdigger::extract_date("No date in this line", timestamp);
    assert(date.empty());
    assert(timestamp == 0);

    std::cout << "  ✓ All date extraction tests passed\n";
}

void test_parse_file() {
    std::cout << "Testing file parsing...\n";

    // Create a test file
    std::string test_file = "test_log.txt";
    std::ofstream out(test_file);
    out << "2024-01-13 10:00:00 Connection from 192.168.1.100\n";
    out << "2024-01-13 10:05:00 Login from 10.0.0.50\n";
    out << "2024-01-13 10:10:00 Access from 192.168.1.100\n";
    out << "No IP address in this line\n";
    out << "2024-01-13 10:15:00 Multiple: 172.16.0.1 and 172.16.0.2\n";
    out.close();

    auto entries = ipdigger::parse_file(test_file);

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

int main() {
    std::cout << "Running IPDigger tests...\n\n";

    try {
        test_extract_ipv4();
        test_extract_ipv6();
        test_extract_date();
        test_parse_file();
        test_generate_statistics();
        test_version();

        std::cout << "\n✓ All tests passed successfully!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}
