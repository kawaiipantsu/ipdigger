#ifndef IPDIGGER_H
#define IPDIGGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <ctime>

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
    time_t first_timestamp;
    time_t last_timestamp;
    std::shared_ptr<EnrichmentData> enrichment;  // Optional enrichment data
};

/**
 * Extract IP addresses (IPv4 and IPv6) from a line of text
 * @param line The text line to parse
 * @return Vector of IP addresses found
 */
std::vector<std::string> extract_ip_addresses(const std::string& line);

/**
 * Check if an IP address is private/local
 * @param ip The IP address to check
 * @return true if the IP is in a private range, false otherwise
 */
bool is_private_ip(const std::string& ip);

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
 * @return Date string if found, empty string otherwise
 */
std::string extract_date(const std::string& line, time_t& timestamp);

/**
 * Parse a file and extract all IP entries
 * @param filename Path to file to parse
 * @param show_progress Show progress bar for large files
 * @param detect_login Detect login status from log lines
 * @return Vector of IPEntry objects
 */
std::vector<IPEntry> parse_file(const std::string& filename, bool show_progress = false, bool detect_login = false);

/**
 * Parse multiple files and extract all IP entries
 * @param filenames Vector of file paths to parse
 * @param show_progress Show progress bar for large files
 * @param detect_login Detect login status from log lines
 * @return Vector of IPEntry objects from all files
 */
std::vector<IPEntry> parse_files(const std::vector<std::string>& filenames, bool show_progress = false, bool detect_login = false);

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
 */
void print_stats_table(const std::map<std::string, IPStats>& stats);

/**
 * Print entries as JSON
 * @param entries Vector of IPEntry objects
 */
void print_json(const std::vector<IPEntry>& entries);

/**
 * Print statistics as JSON
 * @param stats Map of IP statistics
 */
void print_stats_json(const std::map<std::string, IPStats>& stats);

/**
 * Get version information
 * @return Version string
 */
std::string get_version();

} // namespace ipdigger

#endif // IPDIGGER_H
