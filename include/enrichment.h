#ifndef IPDIGGER_ENRICHMENT_H
#define IPDIGGER_ENRICHMENT_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <ctime>
#include "ipdigger.h"
#include "config.h"

namespace ipdigger {

/**
 * Enrichment data for a single IP address
 */
struct EnrichmentData {
    std::string ip_address;
    std::map<std::string, std::string> data;  // Flexible key-value storage
    time_t cached_at;                         // When this was cached
    bool from_cache;                          // Whether loaded from cache

    // Default constructor
    EnrichmentData() : cached_at(0), from_cache(false) {}
};

/**
 * Enrich IP entries with API data
 * @param entries Vector of IPEntry objects (modified in place)
 * @param config Configuration with API providers
 */
void enrich_entries(std::vector<IPEntry>& entries, const Config& config);

/**
 * Enrich statistics with API data
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration (for cache settings)
 */
void enrich_statistics(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Fetch enrichment data for a single IP
 * @param ip_address IP to enrich
 * @param providers List of API providers to query
 * @param config Configuration (for cache settings)
 * @return Enrichment data (may be empty if all providers fail)
 */
EnrichmentData fetch_enrichment(
    const std::string& ip_address,
    const std::vector<APIProvider>& providers,
    const Config& config
);

/**
 * Load enrichment from cache
 * @param ip_address IP address
 * @param cache_dir Cache directory
 * @param cache_ttl_hours Cache TTL in hours
 * @return Pointer to enrichment data if cached and valid, nullptr otherwise
 */
std::shared_ptr<EnrichmentData> load_from_cache(
    const std::string& ip_address,
    const std::string& cache_dir,
    size_t cache_ttl_hours
);

/**
 * Save enrichment to cache
 * @param data Enrichment data to cache
 * @param cache_dir Cache directory
 */
void save_to_cache(const EnrichmentData& data, const std::string& cache_dir);

/**
 * Make HTTP GET request to API
 * @param url Full URL with parameters
 * @param timeout_ms Request timeout in milliseconds
 * @return Response body as string
 */
std::string http_get(const std::string& url, size_t timeout_ms);

/**
 * Generate cache filename for IP address
 * @param ip_address IP to hash
 * @return SHA256 hash of IP (hex string)
 */
std::string get_cache_filename(const std::string& ip_address);

/**
 * Parse API response based on provider type
 * @param provider Provider configuration
 * @param response_json JSON response from API
 * @return Map of enrichment fields
 */
std::map<std::string, std::string> parse_api_response(
    const APIProvider& provider,
    const std::string& response_json
);

/**
 * Replace placeholders in URL template
 * @param url_template URL with {ip} and {api_key} placeholders
 * @param ip_address IP address to insert
 * @param api_key API key to insert
 * @return URL with placeholders replaced
 */
std::string replace_url_placeholders(
    const std::string& url_template,
    const std::string& ip_address,
    const std::string& api_key
);

/**
 * Create directory recursively
 * @param path Directory path to create
 * @return True if successful or already exists
 */
bool create_directory_recursive(const std::string& path);

/**
 * Check if file exists
 * @param filepath Path to file
 * @return True if file exists
 */
bool file_exists(const std::string& filepath);

/**
 * Perform reverse DNS lookup for IP address
 * @param ip_address IP address to lookup
 * @return Hostname if found, empty string otherwise
 */
std::string reverse_dns_lookup(const std::string& ip_address);

/**
 * Find MaxMind database files in known system locations
 * @return Map of database type to file path (city, country)
 */
std::map<std::string, std::string> find_maxmind_databases();

/**
 * Download MaxMind GeoLite2 databases
 * @param account_id MaxMind account ID
 * @param license_key MaxMind license key
 * @param db_dir Directory to store databases
 * @return True if successful
 */
bool download_maxmind_databases(
    const std::string& account_id,
    const std::string& license_key,
    const std::string& db_dir
);

/**
 * Lookup GeoIP information using MaxMind database
 * @param ip_address IP address to lookup
 * @param db_path Path to MaxMind database file
 * @return Map of geo fields (country, country_code, city, etc.)
 */
std::map<std::string, std::string> maxmind_lookup(
    const std::string& ip_address,
    const std::string& db_path
);

/**
 * Enrich entries with reverse DNS
 * @param entries Vector of IPEntry objects (modified in place)
 * @param config Configuration
 */
void enrich_rdns(std::vector<IPEntry>& entries, const Config& config);

/**
 * Enrich entries with MaxMind GeoIP
 * @param entries Vector of IPEntry objects (modified in place)
 * @param config Configuration
 */
void enrich_geoip(std::vector<IPEntry>& entries, const Config& config);

/**
 * Enrich statistics with reverse DNS
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 */
void enrich_rdns_stats(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Enrich statistics with MaxMind GeoIP
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 */
void enrich_geoip_stats(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Enrich statistics with AbuseIPDB data
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 */
void enrich_abuseipdb_stats(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Lookup IP information from AbuseIPDB
 * @param ip_address IP address to lookup
 * @param api_key AbuseIPDB API key
 * @return Map of fields (abuseConfidenceScore, usageType, totalReports, isp)
 */
std::map<std::string, std::string> abuseipdb_lookup(
    const std::string& ip_address,
    const std::string& api_key
);

/**
 * Make HTTP GET request with custom headers
 * @param url Full URL
 * @param headers Map of header names to values
 * @param timeout_ms Request timeout in milliseconds
 * @return Response body as string
 */
std::string http_get_with_headers(
    const std::string& url,
    const std::map<std::string, std::string>& headers,
    size_t timeout_ms
);

/**
 * Enrich statistics with WHOIS data
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 */
void enrich_whois_stats(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Lookup IP information from WHOIS
 * @param ip_address IP address to lookup
 * @return Map of fields (netname, abuse_email, cidr, admin)
 */
std::map<std::string, std::string> whois_lookup(const std::string& ip_address);

/**
 * Enrich statistics with ping data
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 */
void enrich_ping_stats(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Ping a host and measure response time
 * @param ip_address IP address to ping
 * @param ping_count Number of ping attempts
 * @return String with "avg: Xms jitter: Yms" or "DEAD" if unreachable
 */
std::string ping_host(const std::string& ip_address, int ping_count = 3);

/**
 * Enrich statistics with TLS certificate data
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 */
void enrich_tls_stats(std::map<std::string, IPStats>& stats, const Config& config);

/**
 * Retrieve TLS certificate information from an IP address
 * @param ip_address IP address to connect to (port 443)
 * @return Map of fields (tls_cn, tls_issuer, tls_algorithm, tls_created, tls_expires, tls_version, tls_keysize) or empty on error
 */
std::map<std::string, std::string> tls_lookup(const std::string& ip_address);

/**
 * Enrich statistics with HTTP server data
 * @param stats Map of IP statistics (modified in place)
 * @param config Configuration
 * @param follow_redirects Whether to follow HTTP redirects
 */
void enrich_http_stats(std::map<std::string, IPStats>& stats, const Config& config, bool follow_redirects);

/**
 * Retrieve HTTP server information from an IP address
 * @param ip_address IP address to check
 * @param follow_redirects Whether to follow HTTP redirects (default: true)
 * @return Map of fields (http_port, http_status, http_server, http_csp, http_title) or empty if no web server
 */
std::map<std::string, std::string> http_lookup(const std::string& ip_address, bool follow_redirects = true);

} // namespace ipdigger

#endif // IPDIGGER_ENRICHMENT_H
