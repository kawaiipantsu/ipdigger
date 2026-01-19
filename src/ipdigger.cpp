#include "ipdigger.h"
#include "enrichment.h"
#include "regex_cache.h"
#include "progress.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <glob.h>
#include <sys/stat.h>

namespace ipdigger {

std::string get_version() {
    return "2.2.0";
}

// RegexCache implementation
RegexCache::RegexCache() {
    // Pre-compile IPv4 pattern
    ipv4_pattern = std::regex(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"
    );

    // Pre-compile IPv6 pattern
    ipv6_pattern = std::regex(
        R"(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|)"
        R"(\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|)"
        R"(\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|)"
        R"(\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|)"
        R"(\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|)"
        R"(\b::ffff:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"
    );

    // Pre-compile all date patterns
    date_patterns = {
        // Common format: 2024-01-13 12:34:56
        {std::regex(R"((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}))"), "%Y-%m-%d %H:%M:%S"},

        // ISO 8601 / RFC3339: 2024-01-13T12:34:56
        {std::regex(R"((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}))"), "%Y-%m-%dT%H:%M:%S"},

        // Apache/Nginx common log: [13/Jan/2024:12:34:56 +0000]
        {std::regex(R"(\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}))"), "%d/%b/%Y:%H:%M:%S"},

        // Syslog format: Jan 13 12:34:56
        {std::regex(R"((\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))"), "%b %d %H:%M:%S"},

        // Date only: 2024-01-13
        {std::regex(R"((\d{4}-\d{2}-\d{2}))"), "%Y-%m-%d"},
    };
}

// Thread-safe global regex cache
const RegexCache& get_regex_cache() {
    static RegexCache cache;  // Thread-safe in C++11+
    return cache;
}

std::vector<std::string> extract_ip_addresses(const std::string& line, const RegexCache& cache) {
    std::vector<std::string> ip_addresses;

    // Extract IPv4 addresses using pre-compiled pattern
    auto ipv4_begin = std::sregex_iterator(line.begin(), line.end(), cache.ipv4_pattern);
    auto ipv4_end = std::sregex_iterator();
    for (std::sregex_iterator i = ipv4_begin; i != ipv4_end; ++i) {
        ip_addresses.push_back(i->str());
    }

    // Extract IPv6 addresses using pre-compiled pattern
    auto ipv6_begin = std::sregex_iterator(line.begin(), line.end(), cache.ipv6_pattern);
    auto ipv6_end = std::sregex_iterator();
    for (std::sregex_iterator i = ipv6_begin; i != ipv6_end; ++i) {
        ip_addresses.push_back(i->str());
    }

    return ip_addresses;
}

bool is_private_ip(const std::string& ip) {
    // Check for IPv4 private addresses
    if (ip.find('.') != std::string::npos) {
        // Parse IPv4 address
        unsigned int a, b, c, d;
        if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            // Check ranges
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;

            // 10.0.0.0/8
            if (a == 10) return true;

            // 172.16.0.0/12
            if (a == 172 && b >= 16 && b <= 31) return true;

            // 192.168.0.0/16
            if (a == 192 && b == 168) return true;

            // 127.0.0.0/8 (loopback)
            if (a == 127) return true;

            // 169.254.0.0/16 (link-local)
            if (a == 169 && b == 254) return true;

            // 0.0.0.0/8 (current network)
            if (a == 0) return true;
        }
        return false;
    }

    // Check for IPv6 private/local addresses
    if (ip.find(':') != std::string::npos) {
        std::string lower_ip = ip;
        std::transform(lower_ip.begin(), lower_ip.end(), lower_ip.begin(), ::tolower);

        // ::1 (loopback)
        if (lower_ip == "::1") return true;

        // fe80::/10 (link-local) - starts with fe8, fe9, fea, or feb
        if (lower_ip.substr(0, 3) == "fe8" ||
            lower_ip.substr(0, 3) == "fe9" ||
            lower_ip.substr(0, 3) == "fea" ||
            lower_ip.substr(0, 3) == "feb") return true;

        // fc00::/7 (unique local) - starts with fc or fd
        if (lower_ip.substr(0, 2) == "fc" || lower_ip.substr(0, 2) == "fd") return true;

        // ::ffff:x.x.x.x (IPv4-mapped IPv6)
        if (lower_ip.find("::ffff:") == 0) {
            // Extract the IPv4 part and check if it's private
            size_t ipv4_start = lower_ip.find_last_of(':') + 1;
            if (ipv4_start != std::string::npos) {
                std::string ipv4_part = lower_ip.substr(ipv4_start);
                return is_private_ip(ipv4_part);
            }
        }
    }

    return false;
}

bool is_ipv4(const std::string& ip) {
    // IPv4 contains dots but not colons
    return (ip.find('.') != std::string::npos && ip.find(':') == std::string::npos);
}

bool is_ipv6(const std::string& ip) {
    // IPv6 contains colons
    return (ip.find(':') != std::string::npos);
}

bool is_reserved_ip(const std::string& ip) {
    // Check for IPv4 reserved addresses
    if (is_ipv4(ip)) {
        unsigned int a, b, c, d;
        if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            // Check ranges
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;

            // 0.0.0.0/8 - "This network"
            if (a == 0) return true;

            // 10.0.0.0/8 - Private
            if (a == 10) return true;

            // 127.0.0.0/8 - Loopback
            if (a == 127) return true;

            // 169.254.0.0/16 - Link-local
            if (a == 169 && b == 254) return true;

            // 172.16.0.0/12 - Private
            if (a == 172 && b >= 16 && b <= 31) return true;

            // 192.168.0.0/16 - Private
            if (a == 192 && b == 168) return true;

            // 192.0.2.0/24 - Documentation (TEST-NET-1)
            if (a == 192 && b == 0 && c == 2) return true;

            // 198.51.100.0/24 - Documentation (TEST-NET-2)
            if (a == 198 && b == 51 && c == 100) return true;

            // 203.0.113.0/24 - Documentation (TEST-NET-3)
            if (a == 203 && b == 0 && c == 113) return true;

            // 224.0.0.0/4 - Multicast (224-239)
            if (a >= 224 && a <= 239) return true;

            // 240.0.0.0/4 - Reserved for future use (240-255)
            if (a >= 240) return true;
        }
        return false;
    }

    // Check for IPv6 reserved addresses
    if (is_ipv6(ip)) {
        std::string lower_ip = ip;
        std::transform(lower_ip.begin(), lower_ip.end(), lower_ip.begin(), ::tolower);

        // :: or ::0 - Unspecified address
        if (lower_ip == "::" || lower_ip == "::0") return true;

        // ::1 - Loopback
        if (lower_ip == "::1") return true;

        // fe80::/10 - Link-local (starts with fe8, fe9, fea, or feb)
        if (lower_ip.substr(0, 3) == "fe8" ||
            lower_ip.substr(0, 3) == "fe9" ||
            lower_ip.substr(0, 3) == "fea" ||
            lower_ip.substr(0, 3) == "feb") return true;

        // fc00::/7 - Unique local (private) - starts with fc or fd
        if (lower_ip.substr(0, 2) == "fc" || lower_ip.substr(0, 2) == "fd") return true;

        // ff00::/8 - Multicast
        if (lower_ip.substr(0, 2) == "ff") return true;

        // 2001:db8::/32 - Documentation
        if (lower_ip.substr(0, 9) == "2001:db8:" || lower_ip.substr(0, 8) == "2001:db8") return true;

        // ::ffff:x.x.x.x - IPv4-mapped IPv6
        if (lower_ip.find("::ffff:") == 0) {
            // Extract the IPv4 part and check if it's reserved
            size_t ipv4_start = lower_ip.find_last_of(':') + 1;
            if (ipv4_start != std::string::npos) {
                std::string ipv4_part = lower_ip.substr(ipv4_start);
                return is_reserved_ip(ipv4_part);
            }
        }
    }

    return false;
}

bool is_eu_country(const std::string& country_code) {
    // EU member states (27 countries as of 2024)
    static const std::set<std::string> eu_countries = {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE",
        "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
        "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
        "SI", "ES", "SE"
    };

    // Case-insensitive matching
    std::string upper_cc = country_code;
    std::transform(upper_cc.begin(), upper_cc.end(), upper_cc.begin(), ::toupper);

    return eu_countries.count(upper_cc) > 0;
}

bool is_gdpr_country(const std::string& country_code) {
    // GDPR-compliant regions: EU27 + EEA (IS, LI, NO) + UK + Switzerland
    // Total: 32 countries
    static const std::set<std::string> gdpr_countries = {
        // EU member states (27 countries)
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE",
        "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
        "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
        "SI", "ES", "SE",
        // EEA non-EU members (3 countries)
        "IS",  // Iceland
        "LI",  // Liechtenstein
        "NO",  // Norway
        // UK (post-Brexit, UK GDPR)
        "GB",
        // Switzerland (data adequacy decision)
        "CH"
    };

    // Case-insensitive matching
    std::string upper_cc = country_code;
    std::transform(upper_cc.begin(), upper_cc.end(), upper_cc.begin(), ::toupper);

    return gdpr_countries.count(upper_cc) > 0;
}

std::string detect_login_status(const std::string& line) {
    // Convert line to lowercase for case-insensitive matching
    std::string lower_line = line;
    std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

    // Keywords that indicate login failure
    std::vector<std::string> failure_keywords = {
        "failed",
        "failure",
        "fail",
        "wrong password",
        "wrong username",
        "invalid password",
        "invalid username",
        "invalid user",
        "authentication failure",
        "authentication failed",
        "auth failed",
        "auth failure",
        "denied",
        "no access",
        "access denied",
        "blocked",
        "banned",
        "unsuccessful",
        "not allowed",
        "rejected",
        "bad password",
        "incorrect password",
        "incorrect username",
        "login denied",
        "login failed",
        "logon failure",
        "bad login",
        "bad credentials",
        "invalid credentials",
        "unknown user",
        "user not found",
        "no such user",
        "lockout",
        "locked out",
        "too many attempts",
        "brute force"
    };

    // Check if line contains any failure keywords
    for (const auto& keyword : failure_keywords) {
        if (lower_line.find(keyword) != std::string::npos) {
            return "failed";
        }
    }

    // Default to success (we only mark as failed if we find keywords)
    return "success";
}

std::string extract_date(const std::string& line, time_t& timestamp, const RegexCache& cache) {
    timestamp = 0;

    // Try pre-compiled date patterns in order
    for (const auto& [pattern, format] : cache.date_patterns) {
        try {
            std::smatch match;
            if (std::regex_search(line, match, pattern)) {
                std::string date_str = match[1].str();

                // Parse the date string
                std::tm tm = {};
                std::istringstream ss(date_str);
                ss >> std::get_time(&tm, format.c_str());

                if (!ss.fail()) {
                    timestamp = std::mktime(&tm);
                    return date_str;
                }
            }
        } catch (const std::regex_error&) {
            // Skip invalid regex patterns
            continue;
        }
    }

    return "";
}

// Parse relative time string (e.g., "24hours", "7days") to seconds offset
time_t parse_relative_time(const std::string& relative_str) {
    // Pattern: number followed by time unit
    std::regex pattern(R"(^(\d+)(seconds?|minutes?|hours?|days?|weeks?|months?|years?|sec|min|hr|s|m|h|d|w|mo|yr|y)$)",
                       std::regex::icase);
    std::smatch match;

    if (!std::regex_match(relative_str, match, pattern)) {
        throw std::runtime_error("Invalid relative time format: " + relative_str);
    }

    long long number = std::stoll(match[1].str());
    std::string unit = match[2].str();

    // Convert to lowercase for comparison
    std::transform(unit.begin(), unit.end(), unit.begin(), ::tolower);

    // Calculate seconds offset based on unit
    long long seconds_offset = 0;
    if (unit == "second" || unit == "seconds" || unit == "sec" || unit == "s") {
        seconds_offset = number;
    } else if (unit == "minute" || unit == "minutes" || unit == "min" || unit == "m") {
        seconds_offset = number * 60;
    } else if (unit == "hour" || unit == "hours" || unit == "hr" || unit == "h") {
        seconds_offset = number * 3600;
    } else if (unit == "day" || unit == "days" || unit == "d") {
        seconds_offset = number * 86400;
    } else if (unit == "week" || unit == "weeks" || unit == "w") {
        seconds_offset = number * 604800;
    } else if (unit == "month" || unit == "months" || unit == "mo") {
        seconds_offset = number * 2592000;  // 30 days
    } else if (unit == "year" || unit == "years" || unit == "yr" || unit == "y") {
        seconds_offset = number * 31536000;  // 365 days
    } else {
        throw std::runtime_error("Unknown time unit: " + unit);
    }

    // Return current time minus offset
    time_t now = std::time(nullptr);
    return now - seconds_offset;
}

// Parse time string in various formats to time_t
time_t parse_time_string(const std::string& time_str, const RegexCache& cache) {
    // Trim whitespace
    std::string trimmed = time_str;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r"));
    trimmed.erase(trimmed.find_last_not_of(" \t\n\r") + 1);

    // Empty string means no bound
    if (trimmed.empty()) {
        return 0;
    }

    // Check if it's a Unix timestamp (all digits)
    std::regex unix_timestamp_pattern(R"(^\d+$)");
    if (std::regex_match(trimmed, unix_timestamp_pattern)) {
        try {
            return std::stoll(trimmed);
        } catch (const std::exception& e) {
            throw std::runtime_error("Invalid Unix timestamp: " + trimmed);
        }
    }

    // Check if it's a relative time
    std::regex relative_pattern(R"(^\d+(seconds?|minutes?|hours?|days?|weeks?|months?|years?|sec|min|hr|s|m|h|d|w|mo|yr|y)$)",
                                std::regex::icase);
    if (std::regex_match(trimmed, relative_pattern)) {
        return parse_relative_time(trimmed);
    }

    // Try each date pattern from the cache
    for (const auto& pattern_pair : cache.date_patterns) {
        try {
            std::smatch match;
            if (std::regex_search(trimmed, match, pattern_pair.first)) {
                std::string date_str = match[0].str();

                // Parse the date string using the corresponding format
                std::tm tm = {};
                std::istringstream ss(date_str);
                ss >> std::get_time(&tm, pattern_pair.second.c_str());

                if (!ss.fail()) {
                    time_t timestamp = std::mktime(&tm);
                    if (timestamp != -1) {
                        return timestamp;
                    }
                }
            }
        } catch (const std::regex_error&) {
            // Skip invalid regex patterns
            continue;
        }
    }

    throw std::runtime_error("Invalid time format: " + trimmed);
}

// Parse --time-range argument into TimeRange struct
TimeRange parse_time_range_arg(const std::string& range_arg, const RegexCache& cache) {
    TimeRange range;

    // Find the comma separator
    size_t comma_pos = range_arg.find(',');
    if (comma_pos == std::string::npos) {
        throw std::runtime_error("Invalid time range format. Expected 'from,to'. Example: '2024-01-13,2024-01-14' or ',24hours'");
    }

    // Split into from and to parts
    std::string from_str = range_arg.substr(0, comma_pos);
    std::string to_str = range_arg.substr(comma_pos + 1);

    // Parse 'from' time
    try {
        if (!from_str.empty() && from_str.find_first_not_of(" \t\n\r") != std::string::npos) {
            range.start_time = parse_time_string(from_str, cache);
            range.has_start = true;
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid 'from' time: " + std::string(e.what()));
    }

    // Parse 'to' time
    try {
        if (!to_str.empty() && to_str.find_first_not_of(" \t\n\r") != std::string::npos) {
            range.end_time = parse_time_string(to_str, cache);
            range.has_end = true;
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid 'to' time: " + std::string(e.what()));
    }

    // Validate that end is after start
    if (range.has_start && range.has_end && range.end_time < range.start_time) {
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer),
                     "Invalid time range: end time is before start time\nStart: %lld\nEnd:   %lld\nDid you mean to swap them?",
                     (long long)range.start_time, (long long)range.end_time);
        throw std::runtime_error(buffer);
    }

    return range;
}

// Parse time window string (e.g., "5m", "1h", "30s") to seconds
time_t parse_time_window(const std::string& window_str) {
    // Pattern: number followed by time unit
    std::regex pattern(R"(^(\d+)(seconds?|minutes?|hours?|days?|weeks?|months?|years?|sec|min|hr|s|m|h|d|w|mo|yr|y)$)",
                       std::regex::icase);
    std::smatch match;

    if (!std::regex_match(window_str, match, pattern)) {
        throw std::runtime_error("Invalid time window format: " + window_str);
    }

    long long number = std::stoll(match[1].str());
    std::string unit = match[2].str();

    // Convert to lowercase for comparison
    std::transform(unit.begin(), unit.end(), unit.begin(), ::tolower);

    // Calculate seconds based on unit
    if (unit == "second" || unit == "seconds" || unit == "sec" || unit == "s") {
        return number;
    } else if (unit == "minute" || unit == "minutes" || unit == "min" || unit == "m") {
        return number * 60;
    } else if (unit == "hour" || unit == "hours" || unit == "hr" || unit == "h") {
        return number * 3600;
    } else if (unit == "day" || unit == "days" || unit == "d") {
        return number * 86400;
    } else if (unit == "week" || unit == "weeks" || unit == "w") {
        return number * 604800;
    } else if (unit == "month" || unit == "months" || unit == "mo") {
        return number * 2592000;  // 30 days
    } else if (unit == "year" || unit == "years" || unit == "yr" || unit == "y") {
        return number * 31536000;  // 365 days
    } else {
        throw std::runtime_error("Unknown time unit: " + unit);
    }
}

// Detect attack patterns in IP statistics
void detect_attack_patterns(std::map<std::string, IPStats>& stats,
                            bool detect_ddos, bool detect_spray,
                            bool detect_scan, bool detect_bruteforce,
                            size_t threshold, time_t window_seconds,
                            const std::vector<IPEntry>& entries) {
    // Group entries by IP for time-based analysis
    std::map<std::string, std::vector<IPEntry>> ip_entries;
    for (const auto& entry : entries) {
        ip_entries[entry.ip_address].push_back(entry);
    }

    // Analyze each IP's patterns
    for (auto& stat_pair : stats) {
        const std::string& ip = stat_pair.first;
        IPStats& stat = stat_pair.second;

        // Skip if no entries for this IP
        if (ip_entries.find(ip) == ip_entries.end()) {
            continue;
        }

        const auto& ip_entry_list = ip_entries[ip];

        // DDoS Detection: High volume of requests in short time window
        if (detect_ddos) {
            if (stat.first_timestamp > 0 && stat.last_timestamp > 0) {
                time_t time_span = stat.last_timestamp - stat.first_timestamp;
                // If we have threshold+ events within the time window
                if (stat.count >= threshold) {
                    if (time_span <= window_seconds) {
                        stat.is_ddos = true;
                    }
                }
            }
        }

        // Brute Force Detection: Multiple failed login attempts in time window
        if (detect_bruteforce) {
            if (stat.login_failed_count >= threshold) {
                // Check if failed logins occurred within time window
                if (stat.first_timestamp > 0 && stat.last_timestamp > 0) {
                    time_t time_span = stat.last_timestamp - stat.first_timestamp;
                    if (time_span <= window_seconds) {
                        stat.is_bruteforce = true;
                    }
                }
            }
        }

        // Password Spray Detection: Low attempts per target but many different targets
        // This is approximated by detecting IPs with failed logins but low count per occurrence
        if (detect_spray) {
            // Spray attacks typically have:
            // 1. Multiple failed logins (but fewer than brute force)
            // 2. Distributed over time (not all in short window)
            if (stat.login_failed_count >= threshold / 2 && stat.login_failed_count < threshold) {
                if (stat.first_timestamp > 0 && stat.last_timestamp > 0) {
                    time_t time_span = stat.last_timestamp - stat.first_timestamp;
                    // Spread across longer time than brute force
                    if (time_span > window_seconds && time_span < window_seconds * 10) {
                        stat.is_spray = true;
                    }
                }
            }
        }

        // Scan Detection: Many connections in very short time (faster than DDoS)
        if (detect_scan) {
            if (stat.count >= threshold) {
                if (stat.first_timestamp > 0 && stat.last_timestamp > 0) {
                    time_t time_span = stat.last_timestamp - stat.first_timestamp;
                    // Scans are typically very fast - within a fraction of the window
                    if (time_span > 0 && time_span <= window_seconds / 5) {
                        stat.is_scan = true;
                    }
                }
            }
        }
    }
}

// Chunk information for parallel parsing
struct ChunkInfo {
    size_t start_offset;      // Byte offset where chunk starts
    size_t end_offset;        // Byte offset where chunk ends
    size_t start_line_number; // Line number at start of chunk
};

// Calculate chunk boundaries for parallel parsing
static std::vector<ChunkInfo> calculate_chunks(const std::string& filename, size_t num_chunks, size_t min_chunk_size_mb) {
    std::vector<ChunkInfo> chunks;

    // Get file size
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return chunks;  // Return empty if can't open
    }

    size_t file_size = file.tellg();
    file.seekg(0);

    // Minimum chunk size (e.g., 10MB)
    size_t min_chunk_size = min_chunk_size_mb * 1024 * 1024;

    // If file is too small for chunking, return single chunk
    if (file_size < min_chunk_size * 2) {
        ChunkInfo chunk;
        chunk.start_offset = 0;
        chunk.end_offset = file_size;
        chunk.start_line_number = 1;
        chunks.push_back(chunk);
        return chunks;
    }

    // Calculate ideal chunk size
    size_t chunk_size = file_size / num_chunks;
    if (chunk_size < min_chunk_size) {
        chunk_size = min_chunk_size;
        num_chunks = (file_size + chunk_size - 1) / chunk_size;
    }

    // Calculate chunk boundaries, adjusting for line boundaries
    size_t current_offset = 0;
    size_t current_line = 1;

    for (size_t i = 0; i < num_chunks; ++i) {
        ChunkInfo chunk;
        chunk.start_offset = current_offset;
        chunk.start_line_number = current_line;

        // Calculate tentative end offset
        size_t tentative_end = current_offset + chunk_size;
        if (tentative_end >= file_size) {
            // Last chunk goes to end of file
            chunk.end_offset = file_size;
        } else {
            // Seek to tentative end and find next newline
            file.seekg(tentative_end);
            std::string line;
            std::getline(file, line);  // Read to next newline
            chunk.end_offset = file.tellg();

            // If we hit EOF, use file size
            if (file.eof()) {
                chunk.end_offset = file_size;
            }
        }

        chunks.push_back(chunk);

        // Update for next chunk
        current_offset = chunk.end_offset;

        // Count lines in this chunk to update line number
        // This is approximate - we'll recalculate during actual parsing
        if (i < num_chunks - 1) {
            // For line number tracking, we'll handle it during parsing
            current_line = 0;  // Will be calculated during parsing
        }

        if (current_offset >= file_size) {
            break;
        }
    }

    file.close();
    return chunks;
}

// Parse a single chunk of a file
static std::vector<IPEntry> parse_chunk(
    const std::string& filename,
    const ChunkInfo& chunk,
    const RegexCache& cache,
    bool detect_login,
    const std::string& search_string,
    const std::string& search_regex,
    ProgressTracker& progress
) {
    std::vector<IPEntry> entries;
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Compile regex pattern if search_regex is provided
    std::regex regex_pattern;
    bool use_regex = !search_regex.empty();
    if (use_regex) {
        try {
            regex_pattern = std::regex(search_regex, std::regex::icase);
        } catch (const std::regex_error& e) {
            throw std::runtime_error("Invalid regex pattern: " + std::string(e.what()));
        }
    }
    bool use_search = !search_string.empty();

    // Seek to chunk start
    file.seekg(chunk.start_offset);

    std::string line;
    size_t line_number = chunk.start_line_number;
    size_t bytes_read = chunk.start_offset;
    size_t lines_processed = 0;

    // Read lines until we reach chunk end
    while (bytes_read < chunk.end_offset && std::getline(file, line)) {
        line_number++;
        lines_processed++;
        size_t line_bytes = line.length() + 1;
        bytes_read += line_bytes;

        // Extract IP addresses using pre-compiled patterns
        auto ip_addresses = extract_ip_addresses(line, cache);

        if (ip_addresses.empty()) {
            progress.add_bytes(line_bytes);
            // Only update display every 1000 lines to reduce overhead
            if (lines_processed % 1000 == 0) {
                progress.display();
            }
            continue;
        }

        // Extract date using pre-compiled patterns
        time_t timestamp;
        std::string date_str = extract_date(line, timestamp, cache);

        // Detect login status if requested
        std::string login_status = "";
        if (detect_login) {
            login_status = detect_login_status(line);
        }

        // Check if line matches search criteria
        bool line_matches = false;
        if (use_regex) {
            line_matches = std::regex_search(line, regex_pattern);
        } else if (use_search) {
            std::string lower_line = line;
            std::string lower_search = search_string;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);
            std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);
            line_matches = (lower_line.find(lower_search) != std::string::npos);
        } else {
            line_matches = true;
        }

        // Create entries for each IP
        for (const auto& ip : ip_addresses) {
            IPEntry entry;
            entry.ip_address = ip;
            entry.date_string = date_str;
            entry.filename = filename;
            entry.login_status = login_status;
            entry.line_number = line_number;
            entry.timestamp = timestamp;
            entry.matches_search = line_matches;
            entries.push_back(entry);
        }

        progress.add_bytes(line_bytes);
        // Only update display every 1000 lines to reduce overhead
        if (lines_processed % 1000 == 0) {
            progress.display();
        }
    }

    return entries;
}

// Parallel file parsing for large files
std::vector<IPEntry> parse_file_parallel(
    const std::string& filename,
    const RegexCache& cache,
    bool show_progress,
    bool detect_login,
    const std::string& search_string,
    const std::string& search_regex,
    size_t num_threads,
    size_t min_chunk_size_mb
) {
    // Calculate chunks
    auto chunks = calculate_chunks(filename, num_threads, min_chunk_size_mb);

    if (chunks.empty()) {
        throw std::runtime_error("Failed to calculate chunks for: " + filename);
    }

    // If only one chunk, use regular parsing
    if (chunks.size() == 1) {
        return parse_file(filename, cache, show_progress, detect_login, search_string, search_regex);
    }

    // Get file size for progress tracking
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    size_t file_size = file.tellg();
    file.close();

    // Initialize progress tracker
    ProgressTracker progress;
    progress.init(file_size, show_progress, filename);

    // Thread-safe result storage
    std::vector<std::vector<IPEntry>> chunk_results(chunks.size());
    std::atomic<size_t> chunk_index(0);

    // Worker function
    auto worker = [&]() {
        while (true) {
            size_t idx = chunk_index.fetch_add(1);
            if (idx >= chunks.size()) break;

            try {
                chunk_results[idx] = parse_chunk(
                    filename, chunks[idx], cache, detect_login,
                    search_string, search_regex, progress
                );
            } catch (const std::exception& e) {
                std::cerr << "Warning: Error parsing chunk " << idx << ": " << e.what() << "\n";
                chunk_results[idx] = std::vector<IPEntry>();
            }
        }
    };

    // Launch threads
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }

    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }

    // Merge results in order
    std::vector<IPEntry> all_entries;
    for (const auto& chunk_entries : chunk_results) {
        all_entries.insert(all_entries.end(), chunk_entries.begin(), chunk_entries.end());
    }

    // Final progress update
    progress.finish();

    return all_entries;
}

// Parse stdin for IP addresses
std::vector<IPEntry> parse_stdin(const RegexCache& cache, bool detect_login,
                                  const std::string& search_string, const std::string& search_regex) {
    std::vector<IPEntry> entries;

    // Compile regex pattern if search_regex is provided
    std::regex regex_pattern;
    bool use_regex = !search_regex.empty();
    if (use_regex) {
        try {
            regex_pattern = std::regex(search_regex, std::regex::icase);
        } catch (const std::regex_error& e) {
            throw std::runtime_error("Invalid regex pattern: " + std::string(e.what()));
        }
    }
    bool use_search = !search_string.empty();

    std::string line;
    size_t line_number = 0;

    while (std::getline(std::cin, line)) {
        line_number++;

        // Extract all IP addresses from this line using pre-compiled patterns
        auto ip_addresses = extract_ip_addresses(line, cache);

        if (ip_addresses.empty()) {
            continue;
        }

        // Extract date from this line using pre-compiled patterns
        time_t timestamp;
        std::string date_str = extract_date(line, timestamp, cache);

        // Detect login status if requested
        std::string login_status = "";
        if (detect_login) {
            login_status = detect_login_status(line);
        }

        // Check if line matches search criteria
        bool line_matches = false;
        if (use_regex) {
            line_matches = std::regex_search(line, regex_pattern);
        } else if (use_search) {
            // Case-insensitive literal search
            std::string lower_line = line;
            std::string lower_search = search_string;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);
            std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);
            line_matches = (lower_line.find(lower_search) != std::string::npos);
        } else {
            // No search criteria, all lines match
            line_matches = true;
        }

        // Create an entry for each IP address found on this line
        for (const auto& ip : ip_addresses) {
            IPEntry entry;
            entry.ip_address = ip;
            entry.date_string = date_str;
            entry.filename = "(stdin)";
            entry.login_status = login_status;
            entry.line_number = line_number;
            entry.timestamp = timestamp;
            entry.matches_search = line_matches;
            entries.push_back(entry);
        }
    }

    return entries;
}

std::vector<IPEntry> parse_file(const std::string& filename, const RegexCache& cache, bool show_progress, bool detect_login,
                                 const std::string& search_string, const std::string& search_regex) {
    std::vector<IPEntry> entries;
    std::ifstream file(filename);

    // Compile regex pattern if search_regex is provided
    std::regex regex_pattern;
    bool use_regex = !search_regex.empty();
    if (use_regex) {
        try {
            regex_pattern = std::regex(search_regex, std::regex::icase);
        } catch (const std::regex_error& e) {
            throw std::runtime_error("Invalid regex pattern: " + std::string(e.what()));
        }
    }
    bool use_search = !search_string.empty();

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Get file size and initialize progress tracker
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    ProgressTracker progress;
    progress.init(file_size, show_progress, filename);

    std::string line;
    size_t line_number = 0;

    while (std::getline(file, line)) {
        line_number++;
        size_t line_bytes = line.length() + 1;  // +1 for newline

        // Extract all IP addresses from this line using pre-compiled patterns
        auto ip_addresses = extract_ip_addresses(line, cache);

        if (ip_addresses.empty()) {
            // Update progress even if no IPs found
            progress.add_bytes(line_bytes);
            progress.display();
            continue;
        }

        // Extract date from this line using pre-compiled patterns
        time_t timestamp;
        std::string date_str = extract_date(line, timestamp, cache);

        // Detect login status if requested
        std::string login_status = "";
        if (detect_login) {
            login_status = detect_login_status(line);
        }

        // Check if line matches search criteria
        bool line_matches = false;
        if (use_regex) {
            line_matches = std::regex_search(line, regex_pattern);
        } else if (use_search) {
            // Case-insensitive literal search
            std::string lower_line = line;
            std::string lower_search = search_string;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);
            std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);
            line_matches = (lower_line.find(lower_search) != std::string::npos);
        } else {
            // No search criteria, all lines match
            line_matches = true;
        }

        // Create an entry for each IP address found on this line
        for (const auto& ip : ip_addresses) {
            IPEntry entry;
            entry.ip_address = ip;
            entry.date_string = date_str;
            entry.filename = filename;
            entry.login_status = login_status;
            entry.line_number = line_number;
            entry.timestamp = timestamp;
            entry.matches_search = line_matches;
            entries.push_back(entry);
        }

        // Update progress
        progress.add_bytes(line_bytes);
        progress.display();
    }

    // Final progress update
    progress.finish();

    return entries;
}

std::vector<std::string> expand_glob(const std::string& pattern) {
    std::vector<std::string> files;

    // Check if pattern contains glob characters
    if (pattern.find('*') == std::string::npos &&
        pattern.find('?') == std::string::npos &&
        pattern.find('[') == std::string::npos) {
        // No glob characters, treat as regular file
        files.push_back(pattern);
        return files;
    }

    glob_t glob_result;
    std::memset(&glob_result, 0, sizeof(glob_result));

    int result = glob(pattern.c_str(), GLOB_TILDE, nullptr, &glob_result);

    if (result == 0) {
        for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
            std::string filepath = glob_result.gl_pathv[i];

            // Check if it's a regular file
            struct stat st;
            if (stat(filepath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                files.push_back(filepath);
            }
        }
    } else if (result == GLOB_NOMATCH) {
        // No matches found - return pattern as-is to let parse_file handle error
        files.push_back(pattern);
    }

    globfree(&glob_result);
    return files;
}

// Helper function: Parallel file processing
static std::vector<IPEntry> parse_files_parallel(
    const std::vector<std::string>& filenames,
    const RegexCache& cache,
    bool show_progress,
    bool detect_login,
    const std::string& search_string,
    const std::string& search_regex,
    size_t num_threads
) {
    std::vector<IPEntry> all_entries;
    std::mutex entries_mutex;
    std::atomic<size_t> file_index(0);
    std::atomic<size_t> files_completed(0);

    // Worker function
    auto worker = [&]() {
        while (true) {
            size_t idx = file_index.fetch_add(1);
            if (idx >= filenames.size()) break;

            try {
                // Parse file (progress shown per-file)
                auto entries = parse_file(filenames[idx], cache, show_progress, detect_login,
                                         search_string, search_regex);

                // Merge results (thread-safe)
                {
                    std::lock_guard<std::mutex> lock(entries_mutex);
                    all_entries.insert(all_entries.end(), entries.begin(), entries.end());
                }

                files_completed.fetch_add(1);
            } catch (const std::exception& e) {
                // Log error but continue with other files
                std::cerr << "Warning: " << e.what() << "\n";
                files_completed.fetch_add(1);
            }
        }
    };

    // Launch thread pool
    size_t actual_threads = std::min(num_threads, filenames.size());
    std::vector<std::thread> threads;
    threads.reserve(actual_threads);

    for (size_t i = 0; i < actual_threads; ++i) {
        threads.emplace_back(worker);
    }

    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }

    return all_entries;
}

std::vector<IPEntry> parse_files(const std::vector<std::string>& filenames, const RegexCache& cache, bool show_progress, bool detect_login,
                                  const std::string& search_string, const std::string& search_regex) {
    // For single file, use direct parsing
    if (filenames.size() == 1) {
        try {
            return parse_file(filenames[0], cache, show_progress, detect_login, search_string, search_regex);
        } catch (const std::exception& e) {
            std::cerr << "Warning: " << e.what() << "\n";
            return std::vector<IPEntry>();
        }
    }

    // For multiple files, use parallel processing
    // Auto-detect CPU cores
    unsigned int hw_threads = std::thread::hardware_concurrency();
    size_t num_threads = (hw_threads > 0) ? hw_threads : 4;

    return parse_files_parallel(filenames, cache, show_progress, detect_login,
                               search_string, search_regex, num_threads);
}

std::map<std::string, IPStats> generate_statistics(const std::vector<IPEntry>& entries) {
    std::map<std::string, IPStats> stats;

    for (const auto& entry : entries) {
        auto& stat = stats[entry.ip_address];

        if (stat.count == 0) {
            // First occurrence
            stat.ip_address = entry.ip_address;
            stat.first_seen = entry.date_string;
            stat.last_seen = entry.date_string;
            stat.first_timestamp = entry.timestamp;
            stat.last_timestamp = entry.timestamp;
            stat.count = 1;
            stat.login_success_count = 0;
            stat.login_failed_count = 0;
            stat.search_hits = 0;
        } else {
            // Subsequent occurrence
            stat.count++;

            // Update first seen if this is earlier
            if (entry.timestamp > 0 &&
                (stat.first_timestamp == 0 || entry.timestamp < stat.first_timestamp)) {
                stat.first_seen = entry.date_string;
                stat.first_timestamp = entry.timestamp;
            }

            // Update last seen if this is later
            if (entry.timestamp > 0 &&
                (stat.last_timestamp == 0 || entry.timestamp > stat.last_timestamp)) {
                stat.last_seen = entry.date_string;
                stat.last_timestamp = entry.timestamp;
            }
        }

        // Count login statuses
        if (entry.login_status == "success") {
            stat.login_success_count++;
        } else if (entry.login_status == "failed") {
            stat.login_failed_count++;
        }

        // Count search hits
        if (entry.matches_search) {
            stat.search_hits++;
        }
    }

    return stats;
}

void print_table(const std::vector<IPEntry>& entries) {
    if (entries.empty()) {
        std::cout << "No IP addresses found.\n";
        return;
    }

    // Filter to unique IPs only (first occurrence of each)
    std::vector<IPEntry> unique_entries;
    std::set<std::string> seen_ips;

    for (const auto& entry : entries) {
        if (seen_ips.find(entry.ip_address) == seen_ips.end()) {
            unique_entries.push_back(entry);
            seen_ips.insert(entry.ip_address);
        }
    }

    // Check if multiple files were processed
    std::set<std::string> unique_files;
    for (const auto& entry : unique_entries) {
        unique_files.insert(entry.filename);
    }
    bool show_filename = unique_files.size() > 1;

    // Check for enrichment data and collect field names
    std::vector<std::string> enrich_fields;
    std::map<std::string, size_t> enrich_widths;
    for (const auto& entry : unique_entries) {
        if (entry.enrichment && !entry.enrichment->data.empty()) {
            for (const auto& [key, value] : entry.enrichment->data) {
                if (enrich_widths.find(key) == enrich_widths.end()) {
                    enrich_fields.push_back(key);
                    enrich_widths[key] = key.length();
                }
                enrich_widths[key] = std::max(enrich_widths[key], value.length());
            }
        }
    }

    // Calculate column widths
    size_t ip_width = 15;  // Minimum for "IP Address"
    size_t date_width = 19; // Minimum for "Date/Time"
    size_t line_width = 4;  // Minimum for "Line"
    size_t file_width = 8;  // Minimum for "File"

    for (const auto& entry : unique_entries) {
        ip_width = std::max(ip_width, entry.ip_address.length());
        if (!entry.date_string.empty()) {
            date_width = std::max(date_width, entry.date_string.length());
        }
        line_width = std::max(line_width, std::to_string(entry.line_number).length());
        if (show_filename) {
            file_width = std::max(file_width, entry.filename.length());
        }
    }

    // Print header
    size_t separator_width = ip_width + date_width + line_width + 10;
    if (show_filename) {
        separator_width += file_width + 3;
    }
    for (const auto& field : enrich_fields) {
        separator_width += enrich_widths[field] + 3;
    }
    std::string separator(separator_width, '-');
    std::cout << separator << "\n";
    std::cout << "| " << std::left << std::setw(line_width) << "Line"
              << " | " << std::setw(ip_width) << "IP Address"
              << " | " << std::setw(date_width) << "Date/Time";
    if (show_filename) {
        std::cout << " | " << std::setw(file_width) << "File";
    }
    for (const auto& field : enrich_fields) {
        std::cout << " | " << std::setw(enrich_widths[field]) << field;
    }
    std::cout << " |\n";
    std::cout << separator << "\n";

    // Print unique entries
    for (const auto& entry : unique_entries) {
        std::cout << "| " << std::right << std::setw(line_width) << entry.line_number
                  << " | " << std::left << std::setw(ip_width) << entry.ip_address
                  << " | " << std::setw(date_width)
                  << (entry.date_string.empty() ? "(no date)" : entry.date_string);
        if (show_filename) {
            std::cout << " | " << std::setw(file_width) << entry.filename;
        }
        for (const auto& field : enrich_fields) {
            std::string value = "";
            if (entry.enrichment && entry.enrichment->data.count(field)) {
                value = entry.enrichment->data.at(field);
            }
            std::cout << " | " << std::setw(enrich_widths[field]) << value;
        }
        std::cout << " |\n";
    }

    std::cout << "\nTotal: " << unique_entries.size() << " unique IP address(es) found";
    if (show_filename) {
        std::cout << " across " << unique_files.size() << " file(s)";
    }
    std::cout << "\n";
}

void print_stats_table(const std::map<std::string, IPStats>& stats, bool show_search_hits) {
    if (stats.empty()) {
        std::cout << "No IP addresses found.\n";
        return;
    }

    // Check if login detection is enabled
    bool has_login_data = false;
    for (const auto& [ip, stat] : stats) {
        if (stat.login_success_count > 0 || stat.login_failed_count > 0) {
            has_login_data = true;
            break;
        }
    }

    // Check if attack detection is enabled
    bool has_detection_data = false;
    for (const auto& [ip, stat] : stats) {
        if (stat.is_ddos || stat.is_spray || stat.is_scan || stat.is_bruteforce) {
            has_detection_data = true;
            break;
        }
    }

    // Check for enrichment data and collect field names
    std::vector<std::string> enrich_fields;
    std::map<std::string, size_t> enrich_widths;
    for (const auto& [ip, stat] : stats) {
        if (stat.enrichment && !stat.enrichment->data.empty()) {
            for (const auto& [key, value] : stat.enrichment->data) {
                if (enrich_widths.find(key) == enrich_widths.end()) {
                    enrich_fields.push_back(key);
                    // Use custom display name length for special fields
                    size_t header_len = key.length();
                    if (key == "ping") {
                        header_len = std::string("Ping / Alive").length();
                    } else if (key == "tls_cn") {
                        header_len = std::string("CN").length();
                    } else if (key == "tls_issuer") {
                        header_len = std::string("Issuer").length();
                    } else if (key == "tls_algorithm") {
                        header_len = std::string("Algorithm").length();
                    } else if (key == "tls_created") {
                        header_len = std::string("Created").length();
                    } else if (key == "tls_expires") {
                        header_len = std::string("Expires").length();
                    } else if (key == "tls_version") {
                        header_len = std::string("TLS Ver").length();
                    } else if (key == "tls_keysize") {
                        header_len = std::string("KeySize").length();
                    } else if (key == "http_port") {
                        header_len = std::string("Port").length();
                    } else if (key == "http_status") {
                        header_len = std::string("Status").length();
                    } else if (key == "http_server") {
                        header_len = std::string("Server").length();
                    } else if (key == "http_csp") {
                        header_len = std::string("CSP").length();
                    } else if (key == "http_title") {
                        header_len = std::string("Title").length();
                    }
                    enrich_widths[key] = header_len;
                }
                enrich_widths[key] = std::max(enrich_widths[key], value.length());
            }
        }
    }

    // Calculate column widths
    size_t ip_width = 15;
    size_t first_width = 19;
    size_t last_width = 19;
    size_t count_width = 5;
    size_t search_hits_width = 10;  // "SearchHits"
    size_t login_width = 12;  // "OK: 5 F: 10"
    size_t ddos_width = 4;  // "DDoS"
    size_t spray_width = 5;  // "Spray"
    size_t scan_width = 4;  // "Scan"
    size_t bruteforce_width = 10;  // "BruteForce"

    for (const auto& [ip, stat] : stats) {
        ip_width = std::max(ip_width, ip.length());
        if (!stat.first_seen.empty()) {
            first_width = std::max(first_width, stat.first_seen.length());
        }
        if (!stat.last_seen.empty()) {
            last_width = std::max(last_width, stat.last_seen.length());
        }
        count_width = std::max(count_width, std::to_string(stat.count).length());
        if (show_search_hits) {
            search_hits_width = std::max(search_hits_width, std::to_string(stat.search_hits).length());
        }
    }

    // Print header
    size_t separator_width = ip_width + first_width + last_width + count_width + 13;
    if (show_search_hits) {
        separator_width += search_hits_width + 3;
    }
    if (has_login_data) {
        separator_width += login_width + 3;
    }
    if (has_detection_data) {
        separator_width += ddos_width + spray_width + scan_width + bruteforce_width + 12;  // +12 for separators
    }
    for (const auto& field : enrich_fields) {
        separator_width += enrich_widths[field] + 3;
    }
    std::string separator(separator_width, '-');
    std::cout << separator << "\n";
    std::cout << "| " << std::left << std::setw(ip_width) << "IP Address"
              << " | " << std::setw(first_width) << "First Seen"
              << " | " << std::setw(last_width) << "Last Seen"
              << " | " << std::right << std::setw(count_width) << "Count";
    if (show_search_hits) {
        std::cout << " | " << std::right << std::setw(search_hits_width) << "SearchHits";
    }
    if (has_login_data) {
        std::cout << " | " << std::left << std::setw(login_width) << "Login";
    }
    if (has_detection_data) {
        std::cout << " | " << std::left << std::setw(ddos_width) << "DDoS";
        std::cout << " | " << std::left << std::setw(spray_width) << "Spray";
        std::cout << " | " << std::left << std::setw(scan_width) << "Scan";
        std::cout << " | " << std::left << std::setw(bruteforce_width) << "BruteForce";
    }
    for (const auto& field : enrich_fields) {
        // Use custom display names for special fields
        std::string display_name = field;
        if (field == "ping") {
            display_name = "Ping / Alive";
        } else if (field == "tls_cn") {
            display_name = "CN";
        } else if (field == "tls_issuer") {
            display_name = "Issuer";
        } else if (field == "tls_algorithm") {
            display_name = "Algorithm";
        } else if (field == "tls_created") {
            display_name = "Created";
        } else if (field == "tls_expires") {
            display_name = "Expires";
        } else if (field == "tls_version") {
            display_name = "TLS Ver";
        } else if (field == "tls_keysize") {
            display_name = "KeySize";
        } else if (field == "http_port") {
            display_name = "Port";
        } else if (field == "http_status") {
            display_name = "Status";
        } else if (field == "http_server") {
            display_name = "Server";
        } else if (field == "http_csp") {
            display_name = "CSP";
        } else if (field == "http_title") {
            display_name = "Title";
        }
        std::cout << " | " << std::left << std::setw(enrich_widths[field]) << display_name;
    }
    std::cout << " |\n";
    std::cout << separator << "\n";

    // Convert to vector for sorting by count (descending)
    std::vector<IPStats> sorted_stats;
    for (const auto& [ip, stat] : stats) {
        sorted_stats.push_back(stat);
    }
    std::sort(sorted_stats.begin(), sorted_stats.end(),
              [](const IPStats& a, const IPStats& b) { return a.count > b.count; });

    // Print statistics
    for (const auto& stat : sorted_stats) {
        std::cout << "| " << std::left << std::setw(ip_width) << stat.ip_address
                  << " | " << std::setw(first_width)
                  << (stat.first_seen.empty() ? "(no date)" : stat.first_seen)
                  << " | " << std::setw(last_width)
                  << (stat.last_seen.empty() ? "(no date)" : stat.last_seen)
                  << " | " << std::right << std::setw(count_width) << stat.count;
        if (show_search_hits) {
            std::cout << " | " << std::right << std::setw(search_hits_width) << stat.search_hits;
        }
        if (has_login_data) {
            std::string login_str = "OK:" + std::to_string(stat.login_success_count) +
                                   " F:" + std::to_string(stat.login_failed_count);
            std::cout << " | " << std::left << std::setw(login_width) << login_str;
        }
        if (has_detection_data) {
            std::cout << " | " << std::left << std::setw(ddos_width) << (stat.is_ddos ? "Yes" : "No");
            std::cout << " | " << std::left << std::setw(spray_width) << (stat.is_spray ? "Yes" : "No");
            std::cout << " | " << std::left << std::setw(scan_width) << (stat.is_scan ? "Yes" : "No");
            std::cout << " | " << std::left << std::setw(bruteforce_width) << (stat.is_bruteforce ? "Yes" : "No");
        }
        for (const auto& field : enrich_fields) {
            std::string value = "";
            if (stat.enrichment && stat.enrichment->data.count(field)) {
                value = stat.enrichment->data.at(field);
            }
            std::cout << " | " << std::left << std::setw(enrich_widths[field]) << value;
        }
        std::cout << " |\n";
    }

    std::cout << "\nTotal: " << stats.size() << " unique IP address(es)\n";
}

// Helper function to escape JSON strings
static std::string json_escape(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.size());

    for (char c : str) {
        switch (c) {
            case '"':  escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b";  break;
            case '\f': escaped += "\\f";  break;
            case '\n': escaped += "\\n";  break;
            case '\r': escaped += "\\r";  break;
            case '\t': escaped += "\\t";  break;
            default:
                if (c < 0x20) {
                    // Control characters
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    escaped += buf;
                } else {
                    escaped += c;
                }
        }
    }

    return escaped;
}

void print_json(const std::vector<IPEntry>& entries) {
    // Filter to unique IPs only (first occurrence of each)
    std::vector<IPEntry> unique_entries;
    std::set<std::string> seen_ips;

    for (const auto& entry : entries) {
        if (seen_ips.find(entry.ip_address) == seen_ips.end()) {
            unique_entries.push_back(entry);
            seen_ips.insert(entry.ip_address);
        }
    }

    std::cout << "{\n";
    std::cout << "  \"ip_addresses\": [\n";

    // Check if multiple files were processed
    std::set<std::string> unique_files;
    for (const auto& entry : unique_entries) {
        unique_files.insert(entry.filename);
    }
    bool show_filename = unique_files.size() > 1;

    for (size_t i = 0; i < unique_entries.size(); ++i) {
        const auto& entry = unique_entries[i];
        std::cout << "    {\n";
        std::cout << "      \"ip_address\": \"" << json_escape(entry.ip_address) << "\",\n";
        if (show_filename) {
            std::cout << "      \"filename\": \"" << json_escape(entry.filename) << "\",\n";
        }
        std::cout << "      \"line_number\": " << entry.line_number << ",\n";
        std::cout << "      \"date\": ";
        if (entry.date_string.empty()) {
            std::cout << "null";
        } else {
            std::cout << "\"" << json_escape(entry.date_string) << "\"";
        }
        std::cout << ",\n";
        std::cout << "      \"timestamp\": " << entry.timestamp;

        // Add enrichment data if present
        if (entry.enrichment && !entry.enrichment->data.empty()) {
            std::cout << ",\n";
            std::cout << "      \"enrichment\": {\n";
            size_t field_count = 0;
            for (const auto& [key, value] : entry.enrichment->data) {
                if (field_count > 0) std::cout << ",\n";
                std::cout << "        \"" << json_escape(key) << "\": \""
                          << json_escape(value) << "\"";
                field_count++;
            }
            std::cout << "\n      }";
        }

        std::cout << "\n    }";
        if (i < unique_entries.size() - 1) {
            std::cout << ",";
        }
        std::cout << "\n";
    }

    std::cout << "  ],\n";
    std::cout << "  \"total\": " << unique_entries.size() << "\n";
    std::cout << "}\n";
}

void print_stats_json(const std::map<std::string, IPStats>& stats, bool show_search_hits) {
    // Convert to vector for sorting by count (descending)
    std::vector<IPStats> sorted_stats;
    for (const auto& [ip, stat] : stats) {
        sorted_stats.push_back(stat);
    }
    std::sort(sorted_stats.begin(), sorted_stats.end(),
              [](const IPStats& a, const IPStats& b) { return a.count > b.count; });

    std::cout << "{\n";
    std::cout << "  \"statistics\": [\n";

    for (size_t i = 0; i < sorted_stats.size(); ++i) {
        const auto& stat = sorted_stats[i];
        std::cout << "    {\n";
        std::cout << "      \"ip_address\": \"" << json_escape(stat.ip_address) << "\",\n";
        std::cout << "      \"first_seen\": ";
        if (stat.first_seen.empty()) {
            std::cout << "null";
        } else {
            std::cout << "\"" << json_escape(stat.first_seen) << "\"";
        }
        std::cout << ",\n";
        std::cout << "      \"last_seen\": ";
        if (stat.last_seen.empty()) {
            std::cout << "null";
        } else {
            std::cout << "\"" << json_escape(stat.last_seen) << "\"";
        }
        std::cout << ",\n";
        std::cout << "      \"count\": " << stat.count << ",\n";
        std::cout << "      \"first_timestamp\": " << stat.first_timestamp << ",\n";
        std::cout << "      \"last_timestamp\": " << stat.last_timestamp << ",\n";
        std::cout << "      \"login_success_count\": " << stat.login_success_count << ",\n";
        std::cout << "      \"login_failed_count\": " << stat.login_failed_count << ",\n";
        std::cout << "      \"is_ddos\": " << (stat.is_ddos ? "true" : "false") << ",\n";
        std::cout << "      \"is_spray\": " << (stat.is_spray ? "true" : "false") << ",\n";
        std::cout << "      \"is_scan\": " << (stat.is_scan ? "true" : "false") << ",\n";
        std::cout << "      \"is_bruteforce\": " << (stat.is_bruteforce ? "true" : "false");

        if (show_search_hits) {
            std::cout << ",\n";
            std::cout << "      \"search_hits\": " << stat.search_hits;
        }

        // Add enrichment data if present
        if (stat.enrichment && !stat.enrichment->data.empty()) {
            std::cout << ",\n";
            std::cout << "      \"enrichment\": {\n";
            size_t field_count = 0;
            for (const auto& [key, value] : stat.enrichment->data) {
                if (field_count > 0) std::cout << ",\n";
                std::cout << "        \"" << json_escape(key) << "\": \""
                          << json_escape(value) << "\"";
                field_count++;
            }
            std::cout << "\n      }";
        }

        std::cout << "\n    }";
        if (i < sorted_stats.size() - 1) {
            std::cout << ",";
        }
        std::cout << "\n";
    }

    std::cout << "  ],\n";
    std::cout << "  \"total\": " << sorted_stats.size() << "\n";
    std::cout << "}\n";
}

void print_stats_geomap(const std::map<std::string, IPStats>& stats, bool show_search_hits) {
    // Convert to vector for sorting by count (descending)
    std::vector<IPStats> sorted_stats;
    for (const auto& [ip, stat] : stats) {
        sorted_stats.push_back(stat);
    }
    std::sort(sorted_stats.begin(), sorted_stats.end(),
              [](const IPStats& a, const IPStats& b) { return a.count > b.count; });

    std::cout << "{\n";
    std::cout << "  \"type\": \"FeatureCollection\",\n";
    std::cout << "  \"features\": [\n";

    size_t feature_count = 0;
    for (const auto& stat : sorted_stats) {
        // Only include IPs with geo coordinates
        if (!stat.enrichment ||
            stat.enrichment->data.find("latitude") == stat.enrichment->data.end() ||
            stat.enrichment->data.find("longitude") == stat.enrichment->data.end()) {
            continue;  // Skip IPs without coordinates
        }

        if (feature_count > 0) {
            std::cout << ",\n";
        }

        std::string latitude = stat.enrichment->data.at("latitude");
        std::string longitude = stat.enrichment->data.at("longitude");

        std::cout << "    {\n";
        std::cout << "      \"type\": \"Feature\",\n";
        std::cout << "      \"geometry\": {\n";
        std::cout << "        \"type\": \"Point\",\n";
        std::cout << "        \"coordinates\": [" << longitude << ", " << latitude << "]\n";
        std::cout << "      },\n";
        std::cout << "      \"properties\": {\n";
        std::cout << "        \"ip_address\": \"" << json_escape(stat.ip_address) << "\",\n";
        std::cout << "        \"count\": " << stat.count << ",\n";
        std::cout << "        \"first_seen\": ";
        if (stat.first_seen.empty()) {
            std::cout << "null";
        } else {
            std::cout << "\"" << json_escape(stat.first_seen) << "\"";
        }
        std::cout << ",\n";
        std::cout << "        \"last_seen\": ";
        if (stat.last_seen.empty()) {
            std::cout << "null";
        } else {
            std::cout << "\"" << json_escape(stat.last_seen) << "\"";
        }
        std::cout << ",\n";
        std::cout << "        \"first_timestamp\": " << stat.first_timestamp << ",\n";
        std::cout << "        \"last_timestamp\": " << stat.last_timestamp << ",\n";
        std::cout << "        \"login_success_count\": " << stat.login_success_count << ",\n";
        std::cout << "        \"login_failed_count\": " << stat.login_failed_count << ",\n";
        std::cout << "        \"is_ddos\": " << (stat.is_ddos ? "true" : "false") << ",\n";
        std::cout << "        \"is_spray\": " << (stat.is_spray ? "true" : "false") << ",\n";
        std::cout << "        \"is_scan\": " << (stat.is_scan ? "true" : "false") << ",\n";
        std::cout << "        \"is_bruteforce\": " << (stat.is_bruteforce ? "true" : "false");

        if (show_search_hits) {
            std::cout << ",\n";
            std::cout << "        \"search_hits\": " << stat.search_hits;
        }

        // Add all enrichment data (except lat/lon which are already in geometry)
        if (stat.enrichment && !stat.enrichment->data.empty()) {
            for (const auto& [key, value] : stat.enrichment->data) {
                if (key != "latitude" && key != "longitude") {
                    std::cout << ",\n";
                    std::cout << "        \"" << json_escape(key) << "\": \""
                              << json_escape(value) << "\"";
                }
            }
        }

        std::cout << "\n      }\n";
        std::cout << "    }";
        feature_count++;
    }

    std::cout << "\n  ]\n";
    std::cout << "}\n";
}

} // namespace ipdigger
