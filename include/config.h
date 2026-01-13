#ifndef IPDIGGER_CONFIG_H
#define IPDIGGER_CONFIG_H

#include <string>
#include <vector>
#include <map>

namespace ipdigger {

/**
 * API provider configuration
 */
struct APIProvider {
    std::string name;           // Human-readable name (e.g., "IPInfo")
    std::string type;           // Provider type: "geo" or "threat"
    std::string url_template;   // URL with {ip} and {api_key} placeholders
    std::string api_key;        // API key for authentication
    bool enabled;               // Whether this provider is active
    size_t timeout_ms;          // Request timeout in milliseconds
    size_t rate_limit_ms;       // Minimum time between requests

    // Default constructor
    APIProvider()
        : enabled(false), timeout_ms(5000), rate_limit_ms(100) {}
};

/**
 * Global configuration
 */
struct Config {
    // Output settings
    bool default_enrich;        // Enable enrichment by default
    bool default_json;          // Enable JSON output by default

    // Enrichment settings
    bool enrich_geo;            // Enable geolocation enrichment
    bool enrich_threat;         // Enable threat intelligence enrichment
    bool enrich_rdns;           // Enable reverse DNS lookup
    size_t parallel_requests;   // Max concurrent API requests
    size_t rdns_threads;        // Number of threads for reverse DNS lookups

    // Cache settings
    std::string cache_dir;      // Cache directory path
    size_t cache_ttl_hours;     // Cache time-to-live in hours
    bool cache_enabled;         // Enable/disable caching

    // MaxMind settings
    std::string maxmind_db_dir;         // MaxMind database directory
    std::string maxmind_account_id;     // MaxMind account ID for downloads
    std::string maxmind_license_key;    // MaxMind license key for downloads
    bool maxmind_auto_download;         // Auto-download databases if missing

    // AbuseIPDB settings
    std::string abuseipdb_api_key;      // AbuseIPDB API key

    // API providers
    std::vector<APIProvider> providers;

    // Config file path
    std::string config_file_path;

    // Default constructor with sensible defaults
    Config();
};

/**
 * Load configuration from default locations
 * Priority: CLI flags > Environment vars > Config file > Defaults
 * @return Config object with merged settings
 */
Config load_config();

/**
 * Load configuration from specific file
 * @param config_path Path to configuration file
 * @return Config object
 */
Config load_config_from_file(const std::string& config_path);

/**
 * Create default config directory if it doesn't exist
 * @return Path to config directory (~/.ipdigger/)
 */
std::string create_config_directory();

/**
 * Create example config file if it doesn't exist
 * @param config_path Path where to create the example config
 * @return True if created successfully or already exists
 */
bool create_example_config(const std::string& config_path);

/**
 * Get path to config file (~/.ipdigger/settings.conf)
 * @return Config file path
 */
std::string get_config_file_path();

/**
 * Get path to config directory (~/.ipdigger/)
 * @return Config directory path
 */
std::string get_config_directory();

/**
 * Parse INI format configuration file
 * @param filepath Path to INI file
 * @return Map of sections to key-value pairs
 */
std::map<std::string, std::map<std::string, std::string>> parse_ini_file(
    const std::string& filepath
);

/**
 * Parse API providers from configuration section
 * @param provider_section Map of provider configuration keys/values
 * @return Vector of enabled API providers
 */
std::vector<APIProvider> parse_api_providers(
    const std::map<std::string, std::string>& provider_section
);

/**
 * Parse boolean value from string
 * @param value String value ("true", "false", "1", "0", "yes", "no")
 * @return Boolean value
 */
bool parse_bool(const std::string& value);

/**
 * Trim whitespace from string
 * @param str String to trim
 * @return Trimmed string
 */
std::string trim(const std::string& str);

/**
 * Expand home directory (~) in path
 * @param path Path potentially containing ~
 * @return Expanded path
 */
std::string expand_home_dir(const std::string& path);

} // namespace ipdigger

#endif // IPDIGGER_CONFIG_H
