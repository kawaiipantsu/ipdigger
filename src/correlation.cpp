#include "correlation.h"
#include "ipdigger.h"
#include "enrichment.h"
#include "config.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <set>

namespace ipdigger {

// Helper function to convert string to lowercase
static std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Helper function to count delimiter occurrences in a line
static size_t count_delimiter(const std::string& line, char delimiter) {
    return std::count(line.begin(), line.end(), delimiter);
}

// Helper function to calculate standard deviation
static double stddev(const std::vector<size_t>& values) {
    if (values.empty()) return 0.0;

    double sum = 0.0;
    for (size_t val : values) {
        sum += val;
    }
    double mean = sum / values.size();

    double variance = 0.0;
    for (size_t val : values) {
        variance += (val - mean) * (val - mean);
    }
    variance /= values.size();

    return std::sqrt(variance);
}

// CSV format detection
FormatDetectionResult detect_csv_format(const std::vector<std::string>& sample_lines) {
    FormatDetectionResult result;

    if (sample_lines.size() < 2) {
        return result;  // Not enough data
    }

    // Test delimiters
    std::vector<char> delimiters = {',', ';', '|', '\t'};

    struct DelimiterScore {
        char delimiter;
        double score;
        double avg_count;
        size_t field_count;
    };

    std::vector<DelimiterScore> scores;

    for (char delim : delimiters) {
        std::vector<size_t> counts;
        for (const auto& line : sample_lines) {
            if (line.empty()) continue;
            counts.push_back(count_delimiter(line, delim));
        }

        if (counts.empty()) continue;

        // Calculate average and standard deviation
        double sum = 0.0;
        for (size_t count : counts) {
            sum += count;
        }
        double avg = sum / counts.size();

        if (avg < 1.0) continue;  // Need at least one delimiter per line

        double std_dev = stddev(counts);

        // Consistency score: 1 - (stddev / avg)
        // Higher is better (more consistent delimiter count)
        double consistency = (avg > 0) ? (1.0 - (std_dev / avg)) : 0.0;
        if (consistency < 0.0) consistency = 0.0;

        // Overall score: consistency * avg
        double score = consistency * avg;

        // Field count is average count + 1
        size_t field_count = static_cast<size_t>(avg) + 1;

        scores.push_back({delim, score, avg, field_count});
    }

    if (scores.empty()) {
        return result;  // No suitable delimiter found
    }

    // Find delimiter with highest score
    auto best = std::max_element(scores.begin(), scores.end(),
        [](const DelimiterScore& a, const DelimiterScore& b) {
            return a.score < b.score;
        });

    // Require minimum consistency (80% threshold)
    double consistency = (best->avg_count > 0) ?
        (1.0 - (stddev(std::vector<size_t>()) / best->avg_count)) : 0.0;

    // Recalculate consistency properly for the best delimiter
    std::vector<size_t> best_counts;
    for (const auto& line : sample_lines) {
        if (line.empty()) continue;
        best_counts.push_back(count_delimiter(line, best->delimiter));
    }
    double best_stddev = stddev(best_counts);
    consistency = (best->avg_count > 0) ? (1.0 - (best_stddev / best->avg_count)) : 0.0;
    if (consistency < 0.0) consistency = 0.0;

    if (consistency < 0.8 || best->field_count < 2) {
        return result;  // Not consistent enough
    }

    result.detected = true;
    result.delimiter = best->delimiter;
    result.field_count = best->field_count;

    // Detect header row
    // Header typically has alphabetic field names
    if (!sample_lines.empty()) {
        const std::string& first_line = sample_lines[0];
        std::vector<std::string> fields = parse_csv_line(first_line, result.delimiter);

        // Count alphabetic fields
        size_t alpha_fields = 0;
        for (const auto& field : fields) {
            std::string trimmed = trim(field);
            if (!trimmed.empty()) {
                // Check if field starts with a letter
                if (std::isalpha(static_cast<unsigned char>(trimmed[0]))) {
                    alpha_fields++;
                }
            }
        }

        // If most fields are alphabetic, it's likely a header
        if (alpha_fields >= fields.size() / 2) {
            result.has_header = true;
            result.field_map = map_field_names(first_line, result.delimiter);
        }
    }

    return result;
}

// Parse CSV line with quote handling
std::vector<std::string> parse_csv_line(const std::string& line, char delimiter) {
    std::vector<std::string> fields;
    std::string current_field;
    bool in_quotes = false;

    for (size_t i = 0; i < line.length(); ++i) {
        char c = line[i];

        if (c == '"') {
            // Check for escaped quote ("")
            if (in_quotes && i + 1 < line.length() && line[i + 1] == '"') {
                current_field += '"';
                ++i;  // Skip next quote
            } else {
                // Toggle quote state
                in_quotes = !in_quotes;
            }
        } else if (c == delimiter && !in_quotes) {
            // End of field
            fields.push_back(trim(current_field));
            current_field.clear();
        } else {
            current_field += c;
        }
    }

    // Add last field
    fields.push_back(trim(current_field));

    return fields;
}

// Map field names from header
std::map<std::string, size_t> map_field_names(const std::string& header_line, char delimiter) {
    std::map<std::string, size_t> field_map;
    std::vector<std::string> fields = parse_csv_line(header_line, delimiter);

    for (size_t i = 0; i < fields.size(); ++i) {
        std::string normalized = to_lower(trim(fields[i]));
        if (!normalized.empty()) {
            field_map[normalized] = i;
        }
    }

    return field_map;
}

// Extract field value by name
std::string extract_field_value(const std::vector<std::string>& fields,
                                const std::string& field_name,
                                const std::map<std::string, size_t>& field_map) {
    std::string normalized_name = to_lower(trim(field_name));

    auto it = field_map.find(normalized_name);
    if (it != field_map.end() && it->second < fields.size()) {
        return trim(fields[it->second]);
    }

    return "";
}

// Extract domain from hostname
std::string extract_domain(const std::string& hostname) {
    if (hostname.empty()) return hostname;

    // Split by dots
    std::vector<std::string> parts;
    std::stringstream ss(hostname);
    std::string part;

    while (std::getline(ss, part, '.')) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }

    if (parts.size() < 2) {
        return hostname;  // Not enough components
    }

    // Check for special TLDs (co.uk, com.au, etc.)
    std::set<std::string> special_second_level = {"co", "com", "net", "org", "gov", "edu", "ac"};
    std::set<std::string> special_tlds = {"uk", "au", "nz", "za", "br", "jp"};

    if (parts.size() >= 3) {
        std::string second_last = to_lower(parts[parts.size() - 2]);
        std::string last = to_lower(parts[parts.size() - 1]);

        if (special_second_level.count(second_last) && special_tlds.count(last)) {
            // Return last 3 components (e.g., example.co.uk)
            return parts[parts.size() - 3] + "." + parts[parts.size() - 2] + "." + parts[parts.size() - 1];
        }
    }

    // Return last 2 components (e.g., example.com)
    return parts[parts.size() - 2] + "." + parts[parts.size() - 1];
}

// Correlate by user field
std::string correlate_user(const std::string& line, const CorrelationSettings& settings) {
    if (settings.field_name.empty()) return "";

    // Parse CSV line
    std::vector<std::string> fields = parse_csv_line(line, settings.delimiter);

    // Extract field value
    std::string value = extract_field_value(fields, settings.field_name, settings.field_map);

    // Normalize (lowercase)
    if (!value.empty()) {
        value = to_lower(value);
    }

    return value;
}

// Correlate by host field
std::string correlate_host(const std::string& line, const CorrelationSettings& settings) {
    if (settings.field_name.empty()) return "";

    // Parse CSV line
    std::vector<std::string> fields = parse_csv_line(line, settings.delimiter);

    // Extract field value
    std::string value = extract_field_value(fields, settings.field_name, settings.field_map);

    // Optionally extract domain
    if (!value.empty() && settings.extract_domain) {
        value = extract_domain(value);
    }

    // Normalize (lowercase)
    if (!value.empty()) {
        value = to_lower(value);
    }

    return value;
}

// Correlate by custom regex
std::string correlate_custom(const std::string& line, const CorrelationSettings& settings) {
    if (!settings.compiled_regex) return "";

    std::smatch match;
    if (std::regex_search(line, match, *settings.compiled_regex)) {
        // Return first capture group if available, otherwise full match
        if (match.size() > 1) {
            return match[1].str();
        } else {
            return match[0].str();
        }
    }

    return "";
}

// Extract correlation value (dispatcher)
std::string extract_correlation_value(const std::string& line, const CorrelationSettings& settings) {
    switch (settings.type) {
        case CorrelationType::USER:
            return correlate_user(line, settings);
        case CorrelationType::HOST:
            return correlate_host(line, settings);
        case CorrelationType::CUSTOM:
            return correlate_custom(line, settings);
        default:
            return "";
    }
}

// Print statistics table grouped by correlation
void print_stats_table_grouped_by_correlation(
    const std::map<std::string, IPStats>& stats,
    const std::string& label,
    bool search_active) {

    if (stats.empty()) {
        std::cout << "No IP addresses found.\n";
        return;
    }

    // Group by correlation value
    std::map<std::string, std::map<std::string, IPStats>> grouped;
    for (const auto& [ip, stat] : stats) {
        std::string correlation_value = "Unknown";
        if (stat.enrichment && stat.enrichment->data.count("correlation")) {
            correlation_value = stat.enrichment->data.at("correlation");
        }
        grouped[correlation_value][ip] = stat;
    }

    // Sort groups by total count (descending)
    std::vector<std::pair<std::string, size_t>> group_counts;
    for (const auto& [group_name, group_stats] : grouped) {
        size_t total_count = 0;
        for (const auto& [ip, stat] : group_stats) {
            total_count += stat.count;
        }
        group_counts.push_back({group_name, total_count});
    }
    std::sort(group_counts.begin(), group_counts.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Print each group
    for (const auto& [group_name, total_count] : group_counts) {
        size_t unique_ips = grouped[group_name].size();
        std::cout << "\n" << label << ": " << group_name
                  << " (" << unique_ips << " IP" << (unique_ips != 1 ? "s" : "")
                  << ", " << total_count << " event" << (total_count != 1 ? "s" : "") << ")\n";
        std::cout << std::string(80, '=') << "\n";
        print_stats_table(grouped[group_name], search_active);
    }
}

// Print statistics JSON grouped by correlation
void print_stats_json_grouped_by_correlation(
    const std::map<std::string, IPStats>& stats,
    const std::string& label,
    bool search_active) {

    (void)search_active;  // Reserved for future use

    // Group by correlation value
    std::map<std::string, std::map<std::string, IPStats>> grouped;
    for (const auto& [ip, stat] : stats) {
        std::string correlation_value = "unknown";
        if (stat.enrichment && stat.enrichment->data.count("correlation")) {
            correlation_value = stat.enrichment->data.at("correlation");
        }
        grouped[correlation_value][ip] = stat;
    }

    // Sort groups by total count (descending)
    std::vector<std::pair<std::string, size_t>> group_info;
    for (const auto& [group_name, group_stats] : grouped) {
        size_t total_count = 0;
        for (const auto& [ip, stat] : group_stats) {
            total_count += stat.count;
        }
        group_info.push_back({group_name, total_count});
    }
    std::sort(group_info.begin(), group_info.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    std::cout << "{\n";
    std::cout << "  \"groups\": [\n";

    size_t group_idx = 0;
    for (const auto& [group_name, total_count] : group_info) {
        if (group_idx > 0) std::cout << ",\n";

        const auto& group_stats = grouped[group_name];
        size_t unique_ips = group_stats.size();

        std::cout << "    {\n";
        std::cout << "      \"correlation_value\": \"" << json_escape(group_name) << "\",\n";
        std::cout << "      \"label\": \"" << json_escape(label) << "\",\n";
        std::cout << "      \"unique_ips\": " << unique_ips << ",\n";
        std::cout << "      \"total_events\": " << total_count << ",\n";
        std::cout << "      \"ips\": [\n";

        size_t ip_idx = 0;
        for (const auto& [ip, stat] : group_stats) {
            if (ip_idx > 0) std::cout << ",\n";
            std::cout << "        {\n";
            std::cout << "          \"ip_address\": \"" << json_escape(ip) << "\",\n";
            std::cout << "          \"count\": " << stat.count << ",\n";
            std::cout << "          \"first_seen\": ";
            if (stat.first_seen.empty()) {
                std::cout << "null";
            } else {
                std::cout << "\"" << json_escape(stat.first_seen) << "\"";
            }
            std::cout << ",\n";
            std::cout << "          \"last_seen\": ";
            if (stat.last_seen.empty()) {
                std::cout << "null";
            } else {
                std::cout << "\"" << json_escape(stat.last_seen) << "\"";
            }
            std::cout << "\n";
            std::cout << "        }";
            ip_idx++;
        }

        std::cout << "\n      ]\n";
        std::cout << "    }";
        group_idx++;
    }

    std::cout << "\n  ]\n";
    std::cout << "}\n";
}

} // namespace ipdigger
