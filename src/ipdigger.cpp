#include "ipdigger.h"
#include "enrichment.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <set>
#include <glob.h>
#include <sys/stat.h>

namespace ipdigger {

std::string get_version() {
    return "1.0.0";
}

std::vector<std::string> extract_ip_addresses(const std::string& line) {
    std::vector<std::string> ip_addresses;

    // IPv4 regex pattern - matches valid IPv4 addresses
    std::regex ipv4_pattern(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"
    );

    // IPv6 regex pattern - simplified but covers most common cases
    std::regex ipv6_pattern(
        R"(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|)"
        R"(\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|)"
        R"(\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|)"
        R"(\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|)"
        R"(\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|)"
        R"(\b::ffff:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"
    );

    // Extract IPv4 addresses
    auto ipv4_begin = std::sregex_iterator(line.begin(), line.end(), ipv4_pattern);
    auto ipv4_end = std::sregex_iterator();
    for (std::sregex_iterator i = ipv4_begin; i != ipv4_end; ++i) {
        ip_addresses.push_back(i->str());
    }

    // Extract IPv6 addresses
    auto ipv6_begin = std::sregex_iterator(line.begin(), line.end(), ipv6_pattern);
    auto ipv6_end = std::sregex_iterator();
    for (std::sregex_iterator i = ipv6_begin; i != ipv6_end; ++i) {
        ip_addresses.push_back(i->str());
    }

    return ip_addresses;
}

std::string extract_date(const std::string& line, time_t& timestamp) {
    timestamp = 0;

    // Try multiple date formats - patterns tested in order
    std::vector<std::pair<std::string, std::string>> patterns = {
        // Common format: 2024-01-13 12:34:56
        {R"((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}))", "%Y-%m-%d %H:%M:%S"},

        // ISO 8601 / RFC3339: 2024-01-13T12:34:56
        {R"((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}))", "%Y-%m-%dT%H:%M:%S"},

        // Apache/Nginx common log: [13/Jan/2024:12:34:56 +0000]
        {R"(\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}))", "%d/%b/%Y:%H:%M:%S"},

        // Syslog format: Jan 13 12:34:56
        {R"((\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))", "%b %d %H:%M:%S"},

        // Date only: 2024-01-13
        {R"((\d{4}-\d{2}-\d{2}))", "%Y-%m-%d"},
    };

    for (const auto& [pattern_str, format] : patterns) {
        try {
            std::regex pattern(pattern_str);
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

// Helper function to display parsing progress
static void display_parse_progress(size_t bytes_read, size_t file_size, const std::string& filename) {
    int bar_width = 40;
    float progress = static_cast<float>(bytes_read) / file_size;
    int pos = static_cast<int>(bar_width * progress);

    std::cerr << "\rParsing " << filename << "... [";
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cerr << "=";
        else if (i == pos) std::cerr << ">";
        else std::cerr << " ";
    }
    std::cerr << "] " << static_cast<int>(progress * 100) << "%";
    std::cerr.flush();
}

std::vector<IPEntry> parse_file(const std::string& filename, bool show_progress) {
    std::vector<IPEntry> entries;
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Get file size for progress tracking (only show progress for files > 10KB)
    size_t file_size = 0;
    bool should_show_progress = false;
    if (show_progress) {
        file.seekg(0, std::ios::end);
        file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        should_show_progress = (file_size > 10240);  // 10KB minimum
    }

    std::string line;
    size_t line_number = 0;
    size_t bytes_read = 0;
    size_t last_progress_update = 0;

    while (std::getline(file, line)) {
        line_number++;
        bytes_read += line.length() + 1;  // +1 for newline

        // Extract all IP addresses from this line
        auto ip_addresses = extract_ip_addresses(line);

        if (ip_addresses.empty()) {
            // Update progress even if no IPs found
            if (should_show_progress && file_size > 0 && bytes_read - last_progress_update > file_size / 100) {
                display_parse_progress(bytes_read, file_size, filename);
                last_progress_update = bytes_read;
            }
            continue;
        }

        // Extract date from this line
        time_t timestamp;
        std::string date_str = extract_date(line, timestamp);

        // Create an entry for each IP address found on this line
        for (const auto& ip : ip_addresses) {
            IPEntry entry;
            entry.ip_address = ip;
            entry.date_string = date_str;
            entry.filename = filename;
            entry.line_number = line_number;
            entry.timestamp = timestamp;
            entries.push_back(entry);
        }

        // Update progress periodically (every 1% of file)
        if (should_show_progress && file_size > 0 && bytes_read - last_progress_update > file_size / 100) {
            display_parse_progress(bytes_read, file_size, filename);
            last_progress_update = bytes_read;
        }
    }

    // Final progress update
    if (should_show_progress && file_size > 0) {
        display_parse_progress(file_size, file_size, filename);
        std::cerr << "\n";
    }

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

std::vector<IPEntry> parse_files(const std::vector<std::string>& filenames, bool show_progress) {
    std::vector<IPEntry> all_entries;

    for (const auto& filename : filenames) {
        try {
            auto entries = parse_file(filename, show_progress);
            all_entries.insert(all_entries.end(), entries.begin(), entries.end());
        } catch (const std::exception& e) {
            // Log error but continue with other files
            std::cerr << "Warning: " << e.what() << "\n";
        }
    }

    return all_entries;
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

void print_stats_table(const std::map<std::string, IPStats>& stats) {
    if (stats.empty()) {
        std::cout << "No IP addresses found.\n";
        return;
    }

    // Check for enrichment data and collect field names
    std::vector<std::string> enrich_fields;
    std::map<std::string, size_t> enrich_widths;
    for (const auto& [ip, stat] : stats) {
        if (stat.enrichment && !stat.enrichment->data.empty()) {
            for (const auto& [key, value] : stat.enrichment->data) {
                if (enrich_widths.find(key) == enrich_widths.end()) {
                    enrich_fields.push_back(key);
                    enrich_widths[key] = key.length();
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

    for (const auto& [ip, stat] : stats) {
        ip_width = std::max(ip_width, ip.length());
        if (!stat.first_seen.empty()) {
            first_width = std::max(first_width, stat.first_seen.length());
        }
        if (!stat.last_seen.empty()) {
            last_width = std::max(last_width, stat.last_seen.length());
        }
        count_width = std::max(count_width, std::to_string(stat.count).length());
    }

    // Print header
    size_t separator_width = ip_width + first_width + last_width + count_width + 13;
    for (const auto& field : enrich_fields) {
        separator_width += enrich_widths[field] + 3;
    }
    std::string separator(separator_width, '-');
    std::cout << separator << "\n";
    std::cout << "| " << std::left << std::setw(ip_width) << "IP Address"
              << " | " << std::setw(first_width) << "First Seen"
              << " | " << std::setw(last_width) << "Last Seen"
              << " | " << std::right << std::setw(count_width) << "Count";
    for (const auto& field : enrich_fields) {
        std::cout << " | " << std::left << std::setw(enrich_widths[field]) << field;
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

void print_stats_json(const std::map<std::string, IPStats>& stats) {
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
        std::cout << "      \"last_timestamp\": " << stat.last_timestamp;

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

} // namespace ipdigger
