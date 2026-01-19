#ifndef IPDIGGER_H
#define IPDIGGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <ctime>
#include "regex_cache.h"

namespace ipdigger {

// Forward declarations
struct EnrichmentData;
struct CorrelationSettings;

/**
 * Represents a single IP address entry with optional date
 */
struct IPEntry {
    std::string ip_address;
    std::string date_string;
    std::string filename;
    std::string login_status;  // "success", "failed", or empty if not detected
    size_t line_number;
    time_t timestamp;  // Parsed timestamp, 0 if no date found
    bool matches_search;  // Whether this entry matches search criteria
    std::shared_ptr<EnrichmentData> enrichment;  // Optional enrichment data
};

/**
 * Statistics for an IP address
 */
struct IPStats {
    std::string ip_address;
    std::string first_seen;
    std::string last_seen;
    size_t count;
    size_t login_success_count;  // Count of successful logins
    size_t login_failed_count;   // Count of failed logins
    size_t search_hits;  // Count of lines matching search criteria
    time_t first_timestamp;
    time_t last_timestamp;
    std::shared_ptr<EnrichmentData> enrichment;  // Optional enrichment data

    // Attack pattern detection flags
    bool is_ddos;        // High volume of requests in short time
    bool is_spray;       // Password spray attack pattern
    bool is_scan;        // Port/network scanning pattern
    bool is_bruteforce;  // Brute force attack pattern

    IPStats() : count(0), login_success_count(0), login_failed_count(0), search_hits(0),
                first_timestamp(0), last_timestamp(0),
                is_ddos(false), is_spray(false), is_scan(false), is_bruteforce(false) {}
};

/**
 * Time range filter specification
 */
struct TimeRange {
    time_t start_time;      // 0 means no lower bound
    time_t end_time;        // 0 means no upper bound
    bool has_start;         // Whether start_time is set
    bool has_end;           // Whether end_time is set

    TimeRange() : start_time(0), end_time(0), has_start(false), has_end(false) {}

    /**
     * Check if a timestamp falls within this range
     * @param timestamp Unix timestamp to check
     * @param include_no_timestamp If true, include entries with timestamp=0
     */
    bool contains(time_t timestamp, bool include_no_timestamp = false) const {
        if (timestamp == 0) return include_no_timestamp;
        if (has_start && timestamp < start_time) return false;
        if (has_end && timestamp > end_time) return false;
        return true;
    }
};

/**
 * Extract IP addresses (IPv4 and IPv6) from a line of text
 * @param line The text line to parse
 * @param cache Pre-compiled regex patterns for performance
 * @return Vector of IP addresses found
 */
std::vector<std::string> extract_ip_addresses(const std::string& line, const RegexCache& cache);

/**
 * Check if an IP address is private/local
 * @param ip The IP address to check
 * @return true if the IP is in a private range, false otherwise
 */
bool is_private_ip(const std::string& ip);

/**
 * Check if an IP address is reserved (private, loopback, multicast, broadcast, etc.)
 * @param ip The IP address to check
 * @return true if the IP is in a reserved range, false otherwise
 */
bool is_reserved_ip(const std::string& ip);

/**
 * Check if an IP address is IPv4
 * @param ip The IP address to check
 * @return true if the IP is IPv4, false otherwise
 */
bool is_ipv4(const std::string& ip);

/**
 * Check if an IP address is IPv6
 * @param ip The IP address to check
 * @return true if the IP is IPv6, false otherwise
 */
bool is_ipv6(const std::string& ip);

/**
 * Check if a country code belongs to the EU
 * @param country_code Two-letter ISO country code
 * @return true if the country is an EU member state, false otherwise
 */
bool is_eu_country(const std::string& country_code);

/**
 * Check if a country code belongs to GDPR-compliant regions
 * @param country_code Two-letter ISO country code
 * @return true if the country is GDPR-compliant (EU + EEA + UK + CH), false otherwise
 */
bool is_gdpr_country(const std::string& country_code);

/**
 * Detect login status from a line of text
 * @param line The text line to parse
 * @return "failed" if failure keywords found, "success" otherwise
 */
std::string detect_login_status(const std::string& line);

/**
 * Extract date/timestamp from a line of text
 * Supports common formats: ISO8601, RFC3339, Apache/Nginx logs, syslog
 * @param line The text line to parse
 * @param timestamp Output parameter for parsed timestamp
 * @param cache Pre-compiled regex patterns for performance
 * @return Date string if found, empty string otherwise
 */
std::string extract_date(const std::string& line, time_t& timestamp, const RegexCache& cache);

/**
 * Parse a file and extract all IP entries
 * @param filename Path to file to parse
 * @param cache Pre-compiled regex patterns for performance
 * @param show_progress Show progress bar for large files
 * @param detect_login Detect login status from log lines
 * @param search_string Optional literal string to search for (empty = no search)
 * @param search_regex Optional regex pattern to search for (empty = no search)
 * @param correlation_settings Optional correlation settings for IP-field mapping
 * @return Vector of IPEntry objects
 */
std::vector<IPEntry> parse_file(const std::string& filename, const RegexCache& cache, bool show_progress = false, bool detect_login = false,
                                 const std::string& search_string = "", const std::string& search_regex = "",
                                 const CorrelationSettings* correlation_settings = nullptr);

/**
 * Parse stdin for IP addresses
 * @param cache Pre-compiled regex patterns for performance
 * @param detect_login Detect login status from log lines
 * @param search_string Optional literal string to search for (empty = no search)
 * @param search_regex Optional regex pattern to search for (empty = no search)
 * @return Vector of IPEntry objects
 */
std::vector<IPEntry> parse_stdin(const RegexCache& cache, bool detect_login = false,
                                  const std::string& search_string = "", const std::string& search_regex = "");

/**
 * Parse a file with parallel processing (for large files)
 * @param filename Path to file to parse
 * @param cache Pre-compiled regex patterns for performance
 * @param show_progress Show progress bar for large files
 * @param detect_login Detect login status from log lines
 * @param search_string Optional literal string to search for (empty = no search)
 * @param search_regex Optional regex pattern to search for (empty = no search)
 * @param num_threads Number of threads to use
 * @param min_chunk_size_mb Minimum chunk size in MB
 * @param correlation_settings Optional correlation settings for IP-field mapping
 * @return Vector of IPEntry objects
 */
std::vector<IPEntry> parse_file_parallel(const std::string& filename, const RegexCache& cache, bool show_progress, bool detect_login,
                                          const std::string& search_string, const std::string& search_regex,
                                          size_t num_threads, size_t min_chunk_size_mb,
                                          const CorrelationSettings* correlation_settings = nullptr);

/**
 * Parse multiple files and extract all IP entries
 * @param filenames Vector of file paths to parse
 * @param cache Pre-compiled regex patterns for performance
 * @param show_progress Show progress bar for large files
 * @param detect_login Detect login status from log lines
 * @param search_string Optional literal string to search for (empty = no search)
 * @param search_regex Optional regex pattern to search for (empty = no search)
 * @param correlation_settings Optional correlation settings for IP-field mapping
 * @return Vector of IPEntry objects from all files
 */
std::vector<IPEntry> parse_files(const std::vector<std::string>& filenames, const RegexCache& cache, bool show_progress = false, bool detect_login = false,
                                  const std::string& search_string = "", const std::string& search_regex = "",
                                  const CorrelationSettings* correlation_settings = nullptr);

/**
 * Expand glob pattern to list of files
 * @param pattern Glob pattern (e.g., asterisk.log or /var/log/asterisk.log)
 * @return Vector of matching file paths
 */
std::vector<std::string> expand_glob(const std::string& pattern);

/**
 * Generate statistics from IP entries
 * @param entries Vector of IPEntry objects
 * @return Map of IP address to statistics
 */
std::map<std::string, IPStats> generate_statistics(const std::vector<IPEntry>& entries);

/**
 * Print entries as ASCII table
 * @param entries Vector of IPEntry objects
 */
void print_table(const std::vector<IPEntry>& entries);

/**
 * Print statistics as ASCII table
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to display SearchHits column (default: false)
 */
void print_stats_table(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print entries as JSON
 * @param entries Vector of IPEntry objects
 */
void print_json(const std::vector<IPEntry>& entries);

/**
 * Print statistics as JSON
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to include search_hits field (default: false)
 */
void print_stats_json(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics as GeoJSON map (requires geo enrichment with lat/lon)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to include search_hits field (default: false)
 */
void print_stats_geomap(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics table grouped by ASN (requires geo enrichment)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to display SearchHits column (default: false)
 */
void print_stats_table_grouped_by_asn(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics table grouped by country (requires geo enrichment)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to display SearchHits column (default: false)
 */
void print_stats_table_grouped_by_country(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics table grouped by organization (requires geo enrichment)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to display SearchHits column (default: false)
 */
void print_stats_table_grouped_by_org(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics JSON grouped by ASN (requires geo enrichment)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to include search_hits field (default: false)
 */
void print_stats_json_grouped_by_asn(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics JSON grouped by country (requires geo enrichment)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to include search_hits field (default: false)
 */
void print_stats_json_grouped_by_country(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Print statistics JSON grouped by organization (requires geo enrichment)
 * @param stats Map of IP statistics
 * @param show_search_hits Whether to include search_hits field (default: false)
 */
void print_stats_json_grouped_by_org(const std::map<std::string, IPStats>& stats, bool show_search_hits = false);

/**
 * Get version information
 * @return Version string
 */
std::string get_version();

/**
 * Escape string for JSON output
 * @param str String to escape
 * @return Escaped string
 */
std::string json_escape(const std::string& str);

/**
 * Get global regex cache (thread-safe singleton)
 * @return Reference to the global regex cache
 */
const RegexCache& get_regex_cache();

/**
 * Parse relative time string (e.g., "24hours", "7days") to seconds offset
 * @param relative_str Relative time string
 * @return Unix timestamp (current time minus offset)
 */
time_t parse_relative_time(const std::string& relative_str);

/**
 * Parse time string in various formats to time_t
 * @param time_str Time string (Unix timestamp, ISO date, or relative time)
 * @param cache Pre-compiled regex patterns for performance
 * @return Unix timestamp
 */
time_t parse_time_string(const std::string& time_str, const RegexCache& cache);

/**
 * Parse --time-range argument into TimeRange struct
 * @param range_arg Time range argument (format: "from,to")
 * @param cache Pre-compiled regex patterns for performance
 * @return TimeRange struct with parsed boundaries
 */
TimeRange parse_time_range_arg(const std::string& range_arg, const RegexCache& cache);

/**
 * Parse time window string (e.g., "5m", "1h", "30s") to seconds
 * @param window_str Time window string
 * @return Number of seconds
 */
time_t parse_time_window(const std::string& window_str);

/**
 * Detect attack patterns in IP statistics
 * @param stats Map of IP statistics to analyze
 * @param detect_ddos Enable DDoS detection
 * @param detect_spray Enable password spray detection
 * @param detect_scan Enable scan detection
 * @param detect_bruteforce Enable brute force detection
 * @param threshold Event count threshold (default: 10)
 * @param window_seconds Time window in seconds (default: 300 = 5 minutes)
 * @param entries Original entries for pattern analysis
 */
void detect_attack_patterns(std::map<std::string, IPStats>& stats,
                            bool detect_ddos, bool detect_spray,
                            bool detect_scan, bool detect_bruteforce,
                            size_t threshold, time_t window_seconds,
                            const std::vector<IPEntry>& entries);

} // namespace ipdigger

#endif // IPDIGGER_H
