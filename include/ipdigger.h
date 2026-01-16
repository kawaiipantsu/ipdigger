#ifndef IPDIGGER_H
#define IPDIGGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <ctime>
#include "regex_cache.h"

namespace ipdigger {

// Forward declaration for enrichment data
struct EnrichmentData;

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
 * @return Vector of IPEntry objects
 */
std::vector<IPEntry> parse_file(const std::string& filename, const RegexCache& cache, bool show_progress = false, bool detect_login = false,
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
 * @return Vector of IPEntry objects
 */
std::vector<IPEntry> parse_file_parallel(const std::string& filename, const RegexCache& cache, bool show_progress, bool detect_login,
                                          const std::string& search_string, const std::string& search_regex,
                                          size_t num_threads, size_t min_chunk_size_mb);

/**
 * Parse multiple files and extract all IP entries
 * @param filenames Vector of file paths to parse
 * @param cache Pre-compiled regex patterns for performance
 * @param show_progress Show progress bar for large files
 * @param detect_login Detect login status from log lines
 * @param search_string Optional literal string to search for (empty = no search)
 * @param search_regex Optional regex pattern to search for (empty = no search)
 * @return Vector of IPEntry objects from all files
 */
std::vector<IPEntry> parse_files(const std::vector<std::string>& filenames, const RegexCache& cache, bool show_progress = false, bool detect_login = false,
                                  const std::string& search_string = "", const std::string& search_regex = "");

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
 * Get version information
 * @return Version string
 */
std::string get_version();

/**
 * Get global regex cache (thread-safe singleton)
 * @return Reference to the global regex cache
 */
const RegexCache& get_regex_cache();

} // namespace ipdigger

#endif // IPDIGGER_H
