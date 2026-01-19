#ifndef CORRELATION_H
#define CORRELATION_H

#include <string>
#include <vector>
#include <map>
#include <regex>
#include <memory>

namespace ipdigger {

// Forward declarations
struct IPStats;

// Correlation types supported
enum class CorrelationType {
    NONE,
    USER,
    HOST,
    CUSTOM
};

// Result of CSV format detection
struct FormatDetectionResult {
    bool detected;
    char delimiter;
    bool has_header;
    size_t field_count;
    std::map<std::string, size_t> field_map;  // field_name -> column_index

    FormatDetectionResult()
        : detected(false), delimiter(','), has_header(false), field_count(0) {}
};

// Settings for correlation operations
struct CorrelationSettings {
    CorrelationType type;
    std::string field_name;          // For USER/HOST correlation
    std::string custom_regex;        // For CUSTOM correlation
    bool extract_domain;             // For HOST correlation

    // CSV format information (populated by detection)
    char delimiter;
    bool has_header;
    std::map<std::string, size_t> field_map;  // field_name -> column_index
    std::shared_ptr<std::regex> compiled_regex;  // For CUSTOM correlation

    CorrelationSettings()
        : type(CorrelationType::NONE)
        , extract_domain(false)
        , delimiter(',')
        , has_header(false) {}
};

// CSV format detection
FormatDetectionResult detect_csv_format(const std::vector<std::string>& sample_lines);

// CSV parsing
std::vector<std::string> parse_csv_line(const std::string& line, char delimiter);
std::map<std::string, size_t> map_field_names(const std::string& header_line, char delimiter);
std::string extract_field_value(const std::vector<std::string>& fields,
                                const std::string& field_name,
                                const std::map<std::string, size_t>& field_map);

// Domain extraction
std::string extract_domain(const std::string& hostname);

// Correlation value extraction
std::string correlate_user(const std::string& line, const CorrelationSettings& settings);
std::string correlate_host(const std::string& line, const CorrelationSettings& settings);
std::string correlate_custom(const std::string& line, const CorrelationSettings& settings);
std::string extract_correlation_value(const std::string& line, const CorrelationSettings& settings);

// Grouped output functions
void print_stats_table_grouped_by_correlation(
    const std::map<std::string, IPStats>& stats,
    const std::string& label,
    bool search_active);

void print_stats_json_grouped_by_correlation(
    const std::map<std::string, IPStats>& stats,
    const std::string& label,
    bool search_active);

} // namespace ipdigger

#endif // CORRELATION_H
