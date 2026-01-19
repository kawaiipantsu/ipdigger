#include <iostream>
#include <string>
#include <cstring>
#include <set>
#include <algorithm>
#include <thread>
#include <unistd.h>
#include "ipdigger.h"
#include "config.h"
#include "enrichment.h"
#include "compression.h"
#include "correlation.h"

void print_banner() {
    std::cout << "\n";
    std::cout << "     ___________ ____________\n";
    std::cout << "    |     +      )._______.-'\n";
    std::cout << "     `----------'\n";
    std::cout << "\n";
    std::cout << "       IP Digger v" << ipdigger::get_version() << "\n";
    std::cout << "  Your swiss armyknife tool for IP addresses\n";
    std::cout << "\n";
    std::cout << "         by kawaiipantsu\n";
    std::cout << "    THUGSred Hacking Community\n";
    std::cout << "       https://thugs.red\n";
    std::cout << "\n";
}

void print_usage(const char* program_name) {
    print_banner();
    std::cout << "Usage: " << program_name << " [OPTIONS] <filename>\n";
    std::cout << "   or: " << program_name << " [OPTIONS] -\n";
    std::cout << "   or: <command> | " << program_name << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --output-json      Output in JSON format\n";
    std::cout << "  --output-geomap    Output as GeoJSON map (requires --enrich-geo)\n";
    std::cout << "  --enrich-geo       Enrich IPs with geolocation data (MaxMind)\n";
    std::cout << "  --enrich-rdns      Enrich IPs with reverse DNS lookups\n";
    std::cout << "  --enrich-abuseipdb Enrich IPs with AbuseIPDB threat intelligence\n";
    std::cout << "  --enrich-whois     Enrich IPs with WHOIS data (netname, abuse, CIDR, admin)\n";
    std::cout << "  --enrich-ping      Enrich IPs with ping response time and availability\n";
    std::cout << "  --enrich-tls       Enrich IPs with TLS certificate data (CN, dates, version, keysize)\n";
    std::cout << "  --enrich-http      Enrich IPs with HTTP server data (port, status, server, CSP, title)\n";
    std::cout << "  --enrich-thugsred-ti Enrich IPs with THUGSred Threat Intelligence (cached 24h)\n";
    std::cout << "  --follow-redirects Follow HTTP redirects when using --enrich-http\n";
    std::cout << "  --detect-login     Detect and track login attempts (success/failed)\n";
    std::cout << "  --detect-ddos      Detect DDoS attack patterns (high volume in short time)\n";
    std::cout << "  --detect-spray     Detect password spray attack patterns\n";
    std::cout << "  --detect-scan      Detect port/network scanning patterns\n";
    std::cout << "  --detect-bruteforce Detect brute force attack patterns\n";
    std::cout << "  --threshold <N>    Event count threshold for attack detection (default: 10)\n";
    std::cout << "  --window <time>    Time window for attack detection (default: 5m)\n";
    std::cout << "                     Supported units: s (seconds), m (minutes), h (hours), d (days)\n";
    std::cout << "                     Examples: 30s, 5m, 1h, 7d\n";
    std::cout << "  --search <string>  Filter lines by literal string (case-insensitive) and count hits per IP\n";
    std::cout << "  --search-regex <pattern> Filter lines by regex pattern (case-insensitive) and count hits per IP\n";
    std::cout << "  --no-private       Exclude private/local network addresses from output\n";
    std::cout << "  --no-reserved      Exclude reserved IP addresses (private, loopback, multicast, etc.)\n";
    std::cout << "  --no-ipv4          Exclude IPv4 addresses\n";
    std::cout << "  --no-ipv6          Exclude IPv6 addresses\n";
    std::cout << "  --geo-filter-none-eu   Filter to show only IPs outside the EU (auto-enables --enrich-geo)\n";
    std::cout << "  --geo-filter-none-gdpr Filter to show only IPs outside GDPR regions (auto-enables --enrich-geo)\n";
    std::cout << "  --top-limit <N>    Show only top N IPs sorted by count\n";
    std::cout << "  --limit <N>        Show only latest N entries\n";
    std::cout << "  --time-range <from,to>  Filter entries by timestamp (comma-separated)\n";
    std::cout << "                          Formats: Unix timestamp, ISO date, relative time\n";
    std::cout << "                          Omit 'from' for open start: \",2024-01-14\" (entries up to date)\n";
    std::cout << "                          Omit 'to' for open end: \"24hours,\" (entries from time ago to now)\n";
    std::cout << "                          Relative: 24hours, 7days, 1week, 30minutes (time ago)\n";
    std::cout << "                          Examples:\n";
    std::cout << "                            --time-range \"1705136400,1705222800\"\n";
    std::cout << "                            --time-range \"2024-01-13 00:00:00,2024-01-14 00:00:00\"\n";
    std::cout << "                            --time-range \"24hours,\" (last 24 hours)\n";
    std::cout << "                            --time-range \"7days,1day\" (from 7 days ago to 1 day ago)\n";
    std::cout << "  --include-no-timestamp  Include entries without timestamps in time-range filter\n";
    std::cout << "  --group-by-asn     Group results by ASN (auto-enables --enrich-geo)\n";
    std::cout << "  --group-by-country Group results by country (auto-enables --enrich-geo)\n";
    std::cout << "  --group-by-org     Group results by organization (auto-enables --enrich-geo)\n";
    std::cout << "  --correlate-user <field>    Correlate IPs to username/email field (CSV format)\n";
    std::cout << "  --correlate-host <field>    Correlate IPs to hostname/domain field (CSV format)\n";
    std::cout << "  --correlate-custom <regex>  Correlate IPs using custom regex pattern\n";
    std::cout << "  --extract-domain   Extract domain from hostname (use with --correlate-host)\n";
    std::cout << "  --single-threaded  Force single-threaded parsing (disables parallelism)\n";
    std::cout << "  --threads <N>      Number of threads for parsing (default: auto-detect CPU cores)\n";
    std::cout << "  --help             Display this help message\n";
    std::cout << "  --help-extended    Display extended help with examples\n";
    std::cout << "  --help-correlation Display detailed correlation feature guide\n";
    std::cout << "  --version          Display version information\n\n";
    std::cout << "For examples and more detailed information, use: " << program_name << " --help-extended\n\n";
    std::cout << "Configuration:\n";
    std::cout << "  Config file: ~/.ipdigger/settings.conf\n";
    std::cout << "  Cache dir:   ~/.ipdigger/cache/\n";
}

void print_extended_help(const char* program_name) {
    print_banner();
    std::cout << "Usage: " << program_name << " [OPTIONS] <filename>\n";
    std::cout << "   or: " << program_name << " [OPTIONS] -\n";
    std::cout << "   or: <command> | " << program_name << " [OPTIONS]\n\n";
    std::cout << "For option list, use: " << program_name << " --help\n\n";
    std::cout << "Compressed File Support:\n";
    std::cout << "  Automatically detects and processes compressed files by extension\n";
    std::cout << "  Supported formats: .gz (gzip), .bz2 (bzip2), .xz (XZ)\n";
    std::cout << "  Note: Compressed files use single-threaded parsing only\n\n";
    std::cout << "Group-By Features:\n";
    std::cout << "  --group-by-asn     Groups IPs by Autonomous System Number\n";
    std::cout << "  --group-by-country Groups IPs by country code\n";
    std::cout << "  --group-by-org     Groups IPs by organization/netname\n";
    std::cout << "  Output shows group headers with indented IP details\n\n";
    std::cout << "Basic Examples:\n";
    std::cout << "  " << program_name << " /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --no-private /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --top-limit 20 /var/log/auth.log\n";
    std::cout << "  " << program_name << " --limit 100 /var/log/auth.log\n\n";
    std::cout << "Enrichment Examples:\n";
    std::cout << "  NOTE: Some enrichment features require online access to function:\n";
    std::cout << "    - --enrich-abuseipdb (requires API key and internet)\n";
    std::cout << "    - --enrich-thugsred-ti (downloads threat intelligence lists)\n";
    std::cout << "    - --enrich-rdns (performs reverse DNS lookups)\n";
    std::cout << "    - --enrich-whois (performs WHOIS queries)\n";
    std::cout << "    - --enrich-ping (sends ICMP packets to target IPs)\n";
    std::cout << "    - --enrich-tls (connects to HTTPS port 443)\n";
    std::cout << "    - --enrich-http (connects to HTTP ports 80/443)\n";
    std::cout << "    - --enrich-geo (local MaxMind DB, may auto-download if configured)\n\n";
    std::cout << "  " << program_name << " --enrich-geo /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-rdns /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-abuseipdb /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-whois /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-ping /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-tls /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-http /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-http --follow-redirects /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-thugsred-ti /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-geo --enrich-rdns /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-geo --enrich-abuseipdb --top-limit 10 /var/log/auth.log\n\n";
    std::cout << "Group-By Examples:\n";
    std::cout << "  " << program_name << " --group-by-country /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --group-by-asn --top-limit 10 /var/log/auth.log\n";
    std::cout << "  " << program_name << " --group-by-org --output-json /var/log/nginx/access.log\n\n";
    std::cout << "Search and Filter Examples:\n";
    std::cout << "  " << program_name << " --search \"Failed password\" /var/log/auth.log\n";
    std::cout << "  " << program_name << " --search-regex \"error|warning\" /var/log/nginx/error.log\n";
    std::cout << "  " << program_name << " --time-range \"24hours,\" /var/log/auth.log (last 24 hours)\n";
    std::cout << "  " << program_name << " --time-range \"2024-01-13,2024-01-14\" --enrich-geo /var/log/auth.log\n";
    std::cout << "  " << program_name << " --geo-filter-none-eu /var/log/auth.log\n";
    std::cout << "  " << program_name << " --geo-filter-none-gdpr /var/log/auth.log\n\n";
    std::cout << "Attack Detection Examples:\n";
    std::cout << "  " << program_name << " --detect-ddos --detect-bruteforce /var/log/auth.log\n";
    std::cout << "  " << program_name << " --detect-ddos --threshold 20 --window 1m /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --detect-scan --detect-spray --enrich-geo /var/log/auth.log\n\n";
    std::cout << "Compressed Files and Multiple Files:\n";
    std::cout << "  " << program_name << " /var/log/nginx/access.log.gz\n";
    std::cout << "  " << program_name << " --top-limit 10 /var/log/auth.log.bz2\n";
    std::cout << "  " << program_name << " \"/var/log/*.log\"\n";
    std::cout << "  " << program_name << " --top-limit 20 --output-json \"/var/log/*.log\"\n\n";
    std::cout << "Stdin/Pipe Examples:\n";
    std::cout << "  echo \"192.168.1.1\" | " << program_name << "\n";
    std::cout << "  cat ip_list.txt | " << program_name << " --enrich-geo\n";
    std::cout << "  grep \"Failed\" /var/log/auth.log | " << program_name << " --detect-login\n\n";
    std::cout << "Output Formats:\n";
    std::cout << "  " << program_name << " --output-json /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-geo --output-geomap /var/log/auth.log\n\n";
    std::cout << "Configuration:\n";
    std::cout << "  Config file: ~/.ipdigger/settings.conf\n";
    std::cout << "  Cache dir:   ~/.ipdigger/cache/\n";
}

void print_correlation_help(const char* program_name) {
    print_banner();
    std::cout << "IP CORRELATION FEATURE - Detailed Guide\n";
    std::cout << "========================================\n\n";
    std::cout << "IP Correlation maps IP addresses to other fields (usernames, hostnames, or custom patterns)\n";
    std::cout << "from structured log data. Output is grouped by correlation value, making it easy to see\n";
    std::cout << "which users, systems, or patterns are associated with which IP addresses.\n\n";

    std::cout << "CORRELATION TYPES:\n\n";

    std::cout << "1. User Correlation (--correlate-user <field_name>)\n";
    std::cout << "   Maps IP addresses to username or email fields in CSV/delimited logs.\n";
    std::cout << "   Perfect for tracking which users accessed from which IP addresses.\n\n";
    std::cout << "   Examples:\n";
    std::cout << "     " << program_name << " --correlate-user username auth.csv\n";
    std::cout << "     " << program_name << " --correlate-user email login_log.csv\n";
    std::cout << "     " << program_name << " --correlate-user user --output-json access.csv\n\n";

    std::cout << "2. Host Correlation (--correlate-host <field_name>)\n";
    std::cout << "   Maps IP addresses to hostname or domain fields.\n";
    std::cout << "   Use with --extract-domain to automatically extract root domain from FQDNs.\n\n";
    std::cout << "   Examples:\n";
    std::cout << "     " << program_name << " --correlate-host hostname server_log.csv\n";
    std::cout << "     " << program_name << " --correlate-host fqdn --extract-domain dns.csv\n";
    std::cout << "     " << program_name << " --correlate-host server_name --output-json access.csv\n\n";
    std::cout << "   Domain Extraction Examples:\n";
    std::cout << "     mail.example.com     -> example.com\n";
    std::cout << "     api.service.co.uk    -> service.co.uk (handles special TLDs)\n";
    std::cout << "     vpn.corp.example.org -> example.org\n\n";

    std::cout << "3. Custom Correlation (--correlate-custom <regex>)\n";
    std::cout << "   Maps IP addresses using a custom regex pattern.\n";
    std::cout << "   The first capture group (or full match if no groups) is used as the correlation value.\n\n";
    std::cout << "   Examples:\n";
    std::cout << "     " << program_name << " --correlate-custom 'action=(\\w+)' app.log\n";
    std::cout << "     " << program_name << " --correlate-custom 'method=\"(GET|POST)\"' web.log\n";
    std::cout << "     " << program_name << " --correlate-custom 'status=(\\d+)' nginx.log\n\n";

    std::cout << "CSV FORMAT DETECTION:\n\n";
    std::cout << "  Auto-detects CSV format from log files:\n";
    std::cout << "  - Supported delimiters: , (comma), ; (semicolon), | (pipe), \\t (tab)\n";
    std::cout << "  - Header row detection (alphabetic field names)\n";
    std::cout << "  - Requires 80%% delimiter consistency across sample lines\n";
    std::cout << "  - Field names are case-insensitive\n";
    std::cout << "  - Handles quoted fields with embedded delimiters\n\n";
    std::cout << "  Example CSV with header:\n";
    std::cout << "    timestamp,ip,user,action\n";
    std::cout << "    2024-01-13 12:00:00,192.168.1.1,alice@example.com,login\n";
    std::cout << "    2024-01-13 12:05:00,192.168.1.2,bob@example.com,logout\n\n";

    std::cout << "MULTIPLE VALUES PER IP:\n\n";
    std::cout << "  When an IP appears with different correlation values, they are aggregated\n";
    std::cout << "  and displayed as a comma-separated list.\n\n";
    std::cout << "  Example:\n";
    std::cout << "    Input: IP 192.168.1.1 seen with users \"alice\" and \"bob\"\n";
    std::cout << "    Output: correlation column shows \"alice, bob\"\n\n";

    std::cout << "OUTPUT GROUPING:\n\n";
    std::cout << "  Results are automatically grouped by correlation value.\n";
    std::cout << "  Groups are sorted by total event count (descending).\n\n";
    std::cout << "  Table output format:\n";
    std::cout << "    User: alice@example.com (2 IPs, 15 events)\n";
    std::cout << "    ================================================\n";
    std::cout << "    | IP Address  | First Seen | Last Seen | Count |\n";
    std::cout << "    [IP details...]\n\n";
    std::cout << "  JSON output format:\n";
    std::cout << "    {\n";
    std::cout << "      \"groups\": [\n";
    std::cout << "        {\n";
    std::cout << "          \"correlation_value\": \"alice@example.com\",\n";
    std::cout << "          \"label\": \"User\",\n";
    std::cout << "          \"unique_ips\": 2,\n";
    std::cout << "          \"total_events\": 15,\n";
    std::cout << "          \"ips\": [...]\n";
    std::cout << "        }\n";
    std::cout << "      ]\n";
    std::cout << "    }\n\n";

    std::cout << "PRACTICAL USE CASES:\n\n";
    std::cout << "  1. Security Analysis:\n";
    std::cout << "     Find shared credentials: Multiple users from same IP\n";
    std::cout << "       " << program_name << " --correlate-user username auth.log\n\n";
    std::cout << "  2. User Tracking:\n";
    std::cout << "     Track user IP changes: Which IPs each user accessed from\n";
    std::cout << "       " << program_name << " --correlate-user email --output-json login.csv\n\n";
    std::cout << "  3. Network Mapping:\n";
    std::cout << "     Map IPs to infrastructure: Group by hostname or domain\n";
    std::cout << "       " << program_name << " --correlate-host server --extract-domain dns.csv\n\n";
    std::cout << "  4. Pattern Analysis:\n";
    std::cout << "     Analyze by HTTP method, status code, or custom patterns\n";
    std::cout << "       " << program_name << " --correlate-custom 'status=(\\d+)' access.log\n\n";

    std::cout << "LIMITATIONS AND NOTES:\n\n";
    std::cout << "  - Only ONE correlation flag can be used at a time (mutually exclusive)\n";
    std::cout << "  - Requires structured CSV/delimited input for --correlate-user/host\n";
    std::cout << "  - Custom regex works on any text format\n";
    std::cout << "  - CSV detection samples first 20 lines (falls back if detection fails)\n";
    std::cout << "  - Correlation disables parallel parsing (uses single-threaded mode)\n";
    std::cout << "  - Works with compressed files (.gz, .bz2, .xz)\n";
    std::cout << "  - Compatible with all output formats (table, JSON)\n\n";

    std::cout << "COMPLETE EXAMPLE WORKFLOW:\n\n";
    std::cout << "  # Sample CSV file: login_audit.csv\n";
    std::cout << "  timestamp,ip_address,username,action,result\n";
    std::cout << "  2024-01-13 10:00:00,192.168.1.100,alice,login,success\n";
    std::cout << "  2024-01-13 10:15:00,192.168.1.101,bob,login,success\n";
    std::cout << "  2024-01-13 10:30:00,192.168.1.100,alice,logout,success\n";
    std::cout << "  2024-01-13 11:00:00,192.168.1.100,charlie,login,failed\n\n";
    std::cout << "  # Analysis command:\n";
    std::cout << "  " << program_name << " --correlate-user username login_audit.csv\n\n";
    std::cout << "  # Output shows:\n";
    std::cout << "  User: alice, charlie (1 IP, 3 events)\n";
    std::cout << "    IP 192.168.1.100: First=10:00, Last=11:00, Count=3\n";
    std::cout << "  User: bob (1 IP, 1 event)\n";
    std::cout << "    IP 192.168.1.101: First=10:15, Last=10:15, Count=1\n\n";

    std::cout << "For general help: " << program_name << " --help\n";
    std::cout << "For examples:     " << program_name << " --help-extended\n\n";
}

void print_version() {
    std::cout << "\n";
    std::cout << "     ___________ ____________\n";
    std::cout << "    |     +      )._______.-'\n";
    std::cout << "     `----------'\n";
    std::cout << "\n";
    std::cout << "       IP Digger v" << ipdigger::get_version() << "\n";
    std::cout << "  Your swiss armyknife tool for IP addresses\n";
    std::cout << "\n";
    std::cout << "         by kawaiipantsu\n";
    std::cout << "    THUGSred Hacking Community\n";
    std::cout << "       https://thugs.red\n";
    std::cout << "\n";
    std::cout << "A secure log analysis tool for extracting IP addresses\n";
}

enum class GroupByType {
    NONE,
    ASN,
    COUNTRY,
    ORGANIZATION
};

int main(int argc, char* argv[]) {
    // Load configuration
    ipdigger::Config config;
    try {
        config = ipdigger::load_config();
    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to load config: " << e.what() << "\n";
        config = ipdigger::Config();  // Use defaults
    }

    // Get pre-compiled regex cache (needed for time-range parsing)
    const auto& cache = ipdigger::get_regex_cache();

    // Parse command line arguments (CLI overrides config)
    bool output_json = config.default_json;
    bool output_geomap = false;
    bool enable_geo = false;
    bool enable_rdns = false;
    bool enable_abuseipdb = false;
    bool enable_whois = false;
    bool enable_ping = false;
    bool enable_tls = false;
    bool enable_http = false;
    bool enable_thugsred_ti = false;
    bool follow_redirects = false;
    bool no_private = false;
    bool no_reserved = false;
    bool no_ipv4 = false;
    bool no_ipv6 = false;
    bool detect_login = false;
    bool geo_filter_none_eu = false;
    bool geo_filter_none_gdpr = false;
    bool single_threaded = false;
    size_t num_threads = config.parsing_threads;  // 0 = auto-detect
    size_t top_limit = 0;  // 0 means show all (sorted by count)
    size_t limit = 0;  // 0 means show all (latest entries)
    std::string search_string;
    std::string search_regex;
    std::string filename;
    ipdigger::TimeRange time_range;  // Default: no filtering
    bool include_no_timestamp = false;

    // Attack pattern detection
    bool detect_ddos = false;
    bool detect_spray = false;
    bool detect_scan = false;
    bool detect_bruteforce = false;
    size_t attack_threshold = 10;  // Default threshold
    std::string attack_window = "5m";  // Default 5 minutes

    // Group-by functionality
    GroupByType group_by = GroupByType::NONE;

    // Correlation functionality
    ipdigger::CorrelationType correlation_type = ipdigger::CorrelationType::NONE;
    std::string correlation_field;
    std::string correlation_regex;
    bool extract_domain_flag = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--help-extended") {
            print_extended_help(argv[0]);
            return 0;
        } else if (arg == "--help-correlation") {
            print_correlation_help(argv[0]);
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            print_version();
            return 0;
        } else if (arg == "--output-json") {
            output_json = true;
        } else if (arg == "--output-geomap") {
            output_geomap = true;
        } else if (arg == "--enrich-geo") {
            enable_geo = true;
        } else if (arg == "--enrich-rdns") {
            enable_rdns = true;
        } else if (arg == "--enrich-abuseipdb") {
            enable_abuseipdb = true;
        } else if (arg == "--enrich-whois") {
            enable_whois = true;
        } else if (arg == "--enrich-ping") {
            enable_ping = true;
        } else if (arg == "--enrich-tls") {
            enable_tls = true;
        } else if (arg == "--enrich-http") {
            enable_http = true;
        } else if (arg == "--enrich-thugsred-ti") {
            enable_thugsred_ti = true;
        } else if (arg == "--follow-redirects") {
            follow_redirects = true;
        } else if (arg == "--no-private") {
            no_private = true;
        } else if (arg == "--no-reserved") {
            no_reserved = true;
        } else if (arg == "--no-ipv4") {
            no_ipv4 = true;
        } else if (arg == "--no-ipv6") {
            no_ipv6 = true;
        } else if (arg == "--detect-login") {
            detect_login = true;
        } else if (arg == "--detect-ddos") {
            detect_ddos = true;
        } else if (arg == "--detect-spray") {
            detect_spray = true;
        } else if (arg == "--detect-scan") {
            detect_scan = true;
        } else if (arg == "--detect-bruteforce") {
            detect_bruteforce = true;
        } else if (arg == "--threshold") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --threshold requires a number argument\n";
                return 1;
            }
            try {
                attack_threshold = std::stoull(argv[++i]);
            } catch (const std::exception&) {
                std::cerr << "Error: --threshold requires a valid number\n";
                return 1;
            }
        } else if (arg == "--window") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --window requires a time argument (e.g., 5m, 1h, 30s)\n";
                return 1;
            }
            attack_window = argv[++i];
        } else if (arg == "--top-limit") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --top-limit requires a number argument\n";
                return 1;
            }
            try {
                top_limit = std::stoull(argv[++i]);
            } catch (const std::exception&) {
                std::cerr << "Error: --top-limit requires a valid number\n";
                return 1;
            }
        } else if (arg == "--limit") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --limit requires a number argument\n";
                return 1;
            }
            try {
                limit = std::stoull(argv[++i]);
            } catch (const std::exception&) {
                std::cerr << "Error: --limit requires a valid number\n";
                return 1;
            }
        } else if (arg == "--geo-filter-none-eu") {
            geo_filter_none_eu = true;
        } else if (arg == "--geo-filter-none-gdpr") {
            geo_filter_none_gdpr = true;
        } else if (arg == "--search") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --search requires a search string argument\n";
                return 1;
            }
            search_string = argv[++i];
        } else if (arg == "--search-regex") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --search-regex requires a regex pattern argument\n";
                return 1;
            }
            search_regex = argv[++i];
        } else if (arg == "--single-threaded") {
            single_threaded = true;
        } else if (arg == "--group-by-asn") {
            group_by = GroupByType::ASN;
        } else if (arg == "--group-by-country") {
            group_by = GroupByType::COUNTRY;
        } else if (arg == "--group-by-org") {
            group_by = GroupByType::ORGANIZATION;
        } else if (arg == "--correlate-user") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --correlate-user requires a field name argument\n";
                return 1;
            }
            if (correlation_type != ipdigger::CorrelationType::NONE) {
                std::cerr << "Error: Only one correlation flag allowed at a time\n";
                return 1;
            }
            correlation_type = ipdigger::CorrelationType::USER;
            correlation_field = argv[++i];
        } else if (arg == "--correlate-host") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --correlate-host requires a field name argument\n";
                return 1;
            }
            if (correlation_type != ipdigger::CorrelationType::NONE) {
                std::cerr << "Error: Only one correlation flag allowed at a time\n";
                return 1;
            }
            correlation_type = ipdigger::CorrelationType::HOST;
            correlation_field = argv[++i];
        } else if (arg == "--correlate-custom") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --correlate-custom requires a regex pattern argument\n";
                return 1;
            }
            if (correlation_type != ipdigger::CorrelationType::NONE) {
                std::cerr << "Error: Only one correlation flag allowed at a time\n";
                return 1;
            }
            correlation_type = ipdigger::CorrelationType::CUSTOM;
            correlation_regex = argv[++i];
        } else if (arg == "--extract-domain") {
            extract_domain_flag = true;
        } else if (arg == "--threads") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --threads requires a number argument\n";
                return 1;
            }
            try {
                num_threads = std::stoul(argv[++i]);
                if (num_threads == 0) {
                    std::cerr << "Error: --threads must be at least 1 (or omit for auto-detect)\n";
                    return 1;
                }
            } catch (...) {
                std::cerr << "Error: --threads requires a valid number\n";
                return 1;
            }
        } else if (arg == "--time-range") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --time-range requires argument (format: from,to)\n";
                std::cerr << "Examples: --time-range \"2024-01-13,2024-01-14\"\n";
                std::cerr << "          --time-range \",24hours\"\n";
                return 1;
            }
            try {
                time_range = ipdigger::parse_time_range_arg(argv[++i], cache);
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid --time-range: " << e.what() << "\n";
                return 1;
            }
        } else if (arg == "--include-no-timestamp") {
            include_no_timestamp = true;
        } else if (arg == "-") {
            // "-" means stdin
            if (!filename.empty()) {
                std::cerr << "Error: Multiple filenames specified\n";
                std::cerr << "Use --help for usage information\n";
                return 1;
            }
            filename = arg;
        } else if (arg[0] == '-') {
            std::cerr << "Error: Unknown option '" << arg << "'\n";
            std::cerr << "Use --help for usage information\n";
            return 1;
        } else {
            if (!filename.empty()) {
                std::cerr << "Error: Multiple filenames specified\n";
                std::cerr << "Use --help for usage information\n";
                return 1;
            }
            filename = arg;
        }
    }

    // Validate input - check for stdin or filename
    bool use_stdin = false;
    if (filename.empty()) {
        // Check if stdin is available (not a TTY)
        if (!isatty(STDIN_FILENO)) {
            use_stdin = true;
            filename = "-";  // Special marker for stdin
        } else {
            std::cerr << "Error: No filename specified and no data piped to stdin\n";
            std::cerr << "Either provide a filename or pipe data to stdin\n";
            print_usage(argv[0]);
            return 1;
        }
    } else if (filename == "-") {
        use_stdin = true;
    }

    // Auto-enable geo enrichment if geo filtering or geomap output is requested
    if (geo_filter_none_eu || geo_filter_none_gdpr || output_geomap) {
        enable_geo = true;
    }

    // Auto-enable enrichment based on group-by type
    if (group_by == GroupByType::ASN || group_by == GroupByType::COUNTRY || group_by == GroupByType::ORGANIZATION) {
        enable_geo = true;
    }

    // Determine actual thread count
    size_t actual_threads = 1;
    if (!single_threaded) {
        if (num_threads == 0) {
            // Auto-detect CPU cores
            unsigned int hw_threads = std::thread::hardware_concurrency();
            actual_threads = (hw_threads > 0) ? hw_threads : 4;  // Fallback to 4
        } else {
            actual_threads = num_threads;
        }
    }

    try {
        std::vector<ipdigger::IPEntry> entries;
        std::vector<std::string> files;

        if (use_stdin) {
            // Parse from stdin
            entries = ipdigger::parse_stdin(cache, detect_login, search_string, search_regex);
            files.push_back("(stdin)");
        } else {
            // Expand glob pattern to get list of files
            files = ipdigger::expand_glob(filename);

            if (files.empty()) {
                std::cerr << "Error: No files matched pattern: " << filename << "\n";
                return 1;
            }

            // Parse all files (show progress if not in JSON mode)
            bool show_progress = !output_json;

            // Prepare correlation settings if enabled
            ipdigger::CorrelationSettings correlation_settings;
            const ipdigger::CorrelationSettings* correlation_ptr = nullptr;
            if (correlation_type != ipdigger::CorrelationType::NONE) {
                correlation_settings.type = correlation_type;
                correlation_settings.field_name = correlation_field;
                correlation_settings.custom_regex = correlation_regex;
                correlation_settings.extract_domain = extract_domain_flag;

                // Compile custom regex if needed
                if (correlation_type == ipdigger::CorrelationType::CUSTOM && !correlation_regex.empty()) {
                    try {
                        correlation_settings.compiled_regex = std::make_shared<std::regex>(correlation_regex);
                    } catch (const std::regex_error& e) {
                        std::cerr << "Error: Invalid correlation regex pattern: " << e.what() << "\n";
                        return 1;
                    }
                }

                correlation_ptr = &correlation_settings;
            }

            if (files.size() == 1) {
                // Check if file is compressed (compressed files can't use parallel parsing)
                bool is_compressed_file = ipdigger::is_compressed(files[0]);

                // Notify user if compressed file and they requested multiple threads
                if (is_compressed_file && actual_threads > 1 && !output_json) {
                    std::cerr << "Note: Compressed files use single-threaded parsing\n";
                }

                // Single file - use parallel parsing for large uncompressed files
                if (actual_threads > 1 && !is_compressed_file) {
                    entries = ipdigger::parse_file_parallel(
                        files[0], cache, show_progress, detect_login,
                        search_string, search_regex, actual_threads, config.chunk_size_mb,
                        correlation_ptr
                    );
                } else {
                    // Single-threaded (either requested or required for compressed files)
                    entries = ipdigger::parse_file(files[0], cache, show_progress, detect_login,
                                                  search_string, search_regex, correlation_ptr);
                }
            } else {
                // Multiple files - use multi-file parallel parser
                entries = ipdigger::parse_files(files, cache, show_progress, detect_login,
                                               search_string, search_regex, correlation_ptr);
            }
        }

        // Filter out private IPs if requested
        if (no_private) {
            std::vector<ipdigger::IPEntry> filtered_entries;
            for (const auto& entry : entries) {
                if (!ipdigger::is_private_ip(entry.ip_address)) {
                    filtered_entries.push_back(entry);
                }
            }
            entries = filtered_entries;
        }

        // Filter out reserved IPs if requested
        if (no_reserved) {
            std::vector<ipdigger::IPEntry> filtered_entries;
            for (const auto& entry : entries) {
                if (!ipdigger::is_reserved_ip(entry.ip_address)) {
                    filtered_entries.push_back(entry);
                }
            }
            entries = filtered_entries;
        }

        // Filter out IPv4 if requested
        if (no_ipv4) {
            std::vector<ipdigger::IPEntry> filtered_entries;
            for (const auto& entry : entries) {
                if (!ipdigger::is_ipv4(entry.ip_address)) {
                    filtered_entries.push_back(entry);
                }
            }
            entries = filtered_entries;
        }

        // Filter out IPv6 if requested
        if (no_ipv6) {
            std::vector<ipdigger::IPEntry> filtered_entries;
            for (const auto& entry : entries) {
                if (!ipdigger::is_ipv6(entry.ip_address)) {
                    filtered_entries.push_back(entry);
                }
            }
            entries = filtered_entries;
        }

        // Apply top-limit filtering if requested (filter by top N IPs sorted by count)
        std::set<std::string> top_ips;
        if (top_limit > 0) {
            // Generate statistics to get counts
            auto stats = ipdigger::generate_statistics(entries);

            // Convert to vector and sort by count (stats map is already sorted by count from generate_statistics)
            std::vector<ipdigger::IPStats> sorted_stats;
            for (const auto& [ip, stat] : stats) {
                sorted_stats.push_back(stat);
            }
            std::sort(sorted_stats.begin(), sorted_stats.end(),
                      [](const ipdigger::IPStats& a, const ipdigger::IPStats& b) {
                          return a.count > b.count;
                      });

            // Take top N by count
            size_t count = 0;
            for (const auto& stat : sorted_stats) {
                if (count >= top_limit) break;
                top_ips.insert(stat.ip_address);
                count++;
            }

            // Filter entries to only those in top N
            std::vector<ipdigger::IPEntry> filtered_entries;
            for (const auto& entry : entries) {
                if (top_ips.count(entry.ip_address)) {
                    filtered_entries.push_back(entry);
                }
            }
            entries = filtered_entries;
        }

        // Apply limit filtering if requested (take latest entries)
        if (limit > 0 && entries.size() > limit) {
            // Take the last N entries (latest ones)
            entries = std::vector<ipdigger::IPEntry>(
                entries.end() - limit,
                entries.end()
            );
        }

        // Apply time-range filtering if requested
        if (time_range.has_start || time_range.has_end) {
            std::vector<ipdigger::IPEntry> filtered_entries;
            size_t excluded_count = 0;
            size_t no_timestamp_count = 0;

            for (const auto& entry : entries) {
                if (entry.timestamp == 0) {
                    no_timestamp_count++;
                }

                if (time_range.contains(entry.timestamp, include_no_timestamp)) {
                    filtered_entries.push_back(entry);
                } else {
                    excluded_count++;
                }
            }

            // Show filtering info (only in non-JSON mode)
            if (!output_json && excluded_count > 0) {
                std::cerr << "Filtered out " << excluded_count
                          << " entries outside time range";
                if (no_timestamp_count > 0 && !include_no_timestamp) {
                    std::cerr << " (" << no_timestamp_count << " had no timestamp)";
                }
                std::cerr << "\n";
            }

            entries = filtered_entries;
        }

        if (entries.empty()) {
            if (!output_json) {
                std::cout << "No IP addresses found";
                if (files.size() == 1) {
                    std::cout << " in " << files[0];
                } else {
                    std::cout << " in " << files.size() << " file(s)";
                }
                std::cout << "\n";
            } else {
                // Output empty JSON
                std::cout << "{\"statistics\": [], \"total\": 0}\n";
            }
            return 0;
        }

        // Generate statistics (always, for efficient output)
        auto stats = ipdigger::generate_statistics(entries);

        // Detect attack patterns if requested
        if (detect_ddos || detect_spray || detect_scan || detect_bruteforce) {
            time_t window_seconds;
            try {
                window_seconds = ipdigger::parse_time_window(attack_window);
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid --window value: " << e.what() << "\n";
                return 1;
            }

            ipdigger::detect_attack_patterns(stats, detect_ddos, detect_spray, detect_scan, detect_bruteforce,
                                              attack_threshold, window_seconds, entries);
        }

        // Enrich statistics if requested
        if (enable_geo || enable_rdns || enable_abuseipdb || enable_whois || enable_ping || enable_tls || enable_http || enable_thugsred_ti) {
            if (enable_geo) {
                if (!output_json) std::cout << "Enriching with GeoIP data...\n";
                ipdigger::enrich_geoip_stats(stats, config);
            }

            if (enable_rdns) {
                ipdigger::enrich_rdns_stats(stats, config);
            }

            if (enable_abuseipdb) {
                ipdigger::enrich_abuseipdb_stats(stats, config);
            }

            if (enable_whois) {
                ipdigger::enrich_whois_stats(stats, config);
            }

            if (enable_ping) {
                ipdigger::enrich_ping_stats(stats, config);
            }

            if (enable_tls) {
                ipdigger::enrich_tls_stats(stats, config);
            }

            if (enable_http) {
                ipdigger::enrich_http_stats(stats, config, follow_redirects);
            }

            if (enable_thugsred_ti) {
                ipdigger::enrich_thugsred_ti_stats(stats, config.cache_dir, config.thugsred_ti_cache_hours);
            }
        }

        // Apply EU geo-filtering if requested
        if (geo_filter_none_eu) {
            std::map<std::string, ipdigger::IPStats> filtered_stats;
            size_t skipped_count = 0;

            for (const auto& [ip, stat] : stats) {
                // Check if enrichment data exists and has country code
                bool is_eu = false;

                if (stat.enrichment && stat.enrichment->data.count("cc")) {
                    std::string country_code = stat.enrichment->data.at("cc");
                    is_eu = ipdigger::is_eu_country(country_code);
                }
                // IPs without country codes are included (benefit of doubt)

                if (!is_eu) {
                    filtered_stats[ip] = stat;
                } else {
                    skipped_count++;
                }
            }

            // Show filtering info (only in non-JSON/non-GeoMap mode)
            if (!output_json && !output_geomap && skipped_count > 0) {
                std::cerr << "Filtered out " << skipped_count << " EU IP(s)\n";
            }

            stats = filtered_stats;
        }

        // Apply GDPR geo-filtering if requested
        if (geo_filter_none_gdpr) {
            std::map<std::string, ipdigger::IPStats> filtered_stats;
            size_t skipped_count = 0;

            for (const auto& [ip, stat] : stats) {
                // Check if enrichment data exists and has country code
                bool is_gdpr = false;

                if (stat.enrichment && stat.enrichment->data.count("cc")) {
                    std::string country_code = stat.enrichment->data.at("cc");
                    is_gdpr = ipdigger::is_gdpr_country(country_code);
                }
                // IPs without country codes are included (benefit of doubt)

                if (!is_gdpr) {
                    filtered_stats[ip] = stat;
                } else {
                    skipped_count++;
                }
            }

            // Show filtering info (only in non-JSON/non-GeoMap mode)
            if (!output_json && !output_geomap && skipped_count > 0) {
                std::cerr << "Filtered out " << skipped_count << " GDPR-compliant region IP(s)\n";
            }

            stats = filtered_stats;
        }

        // Display results (always use statistics output)
        bool search_active = !search_string.empty() || !search_regex.empty();

        // Correlation output takes priority over other grouping
        if (correlation_type != ipdigger::CorrelationType::NONE) {
            std::string label = "Correlation";
            if (correlation_type == ipdigger::CorrelationType::USER) {
                label = "User";
            } else if (correlation_type == ipdigger::CorrelationType::HOST) {
                label = "Host";
            } else if (correlation_type == ipdigger::CorrelationType::CUSTOM) {
                label = "Custom";
            }

            if (output_json) {
                ipdigger::print_stats_json_grouped_by_correlation(stats, label, search_active);
            } else {
                ipdigger::print_stats_table_grouped_by_correlation(stats, label, search_active);
            }
        } else if (output_geomap) {
            ipdigger::print_stats_geomap(stats, search_active);
        } else if (output_json) {
            // JSON output with optional grouping
            if (group_by == GroupByType::ASN) {
                ipdigger::print_stats_json_grouped_by_asn(stats, search_active);
            } else if (group_by == GroupByType::COUNTRY) {
                ipdigger::print_stats_json_grouped_by_country(stats, search_active);
            } else if (group_by == GroupByType::ORGANIZATION) {
                ipdigger::print_stats_json_grouped_by_org(stats, search_active);
            } else {
                ipdigger::print_stats_json(stats, search_active);
            }
        } else {
            // Table output with optional grouping
            if (group_by == GroupByType::ASN) {
                ipdigger::print_stats_table_grouped_by_asn(stats, search_active);
            } else if (group_by == GroupByType::COUNTRY) {
                ipdigger::print_stats_table_grouped_by_country(stats, search_active);
            } else if (group_by == GroupByType::ORGANIZATION) {
                ipdigger::print_stats_table_grouped_by_org(stats, search_active);
            } else {
                ipdigger::print_stats_table(stats, search_active);
            }
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
