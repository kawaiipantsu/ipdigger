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

void print_usage(const char* program_name) {
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
    std::cout << "  --follow-redirects Follow HTTP redirects when using --enrich-http\n";
    std::cout << "  --detect-login     Detect and track login attempts (success/failed)\n";
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
    std::cout << "                          Omit 'from' for open start: \",24hours\"\n";
    std::cout << "                          Omit 'to' for open end: \"2024-01-13,\"\n";
    std::cout << "                          Relative: 24hours, 7days, 1week, 30minutes\n";
    std::cout << "                          Examples:\n";
    std::cout << "                            --time-range \"1705136400,1705222800\"\n";
    std::cout << "                            --time-range \"2024-01-13 00:00:00,2024-01-14 00:00:00\"\n";
    std::cout << "                            --time-range \",24hours\"\n";
    std::cout << "                            --time-range \"7days,1day\"\n";
    std::cout << "  --include-no-timestamp  Include entries without timestamps in time-range filter\n";
    std::cout << "  --single-threaded  Force single-threaded parsing (disables parallelism)\n";
    std::cout << "  --threads <N>      Number of threads for parsing (default: auto-detect CPU cores)\n";
    std::cout << "  --help             Display this help message\n";
    std::cout << "  --version          Display version information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --no-private /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-geo /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-rdns /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-abuseipdb /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-whois /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-ping /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-tls /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-http /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-http --follow-redirects /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --search \"Failed password\" /var/log/auth.log\n";
    std::cout << "  " << program_name << " --search-regex \"error|warning\" /var/log/nginx/error.log\n";
    std::cout << "  " << program_name << " --enrich-geo --enrich-rdns /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-geo --enrich-abuseipdb --top-limit 10 /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-geo --output-geomap /var/log/auth.log\n";
    std::cout << "  " << program_name << " --geo-filter-none-eu /var/log/auth.log\n";
    std::cout << "  " << program_name << " --geo-filter-none-gdpr /var/log/auth.log\n";
    std::cout << "  " << program_name << " --top-limit 20 --output-json \"/var/log/*.log\"\n";
    std::cout << "  " << program_name << " --limit 100 /var/log/auth.log\n";
    std::cout << "  " << program_name << " --time-range \",24hours\" /var/log/auth.log\n";
    std::cout << "  " << program_name << " --time-range \"2024-01-13,2024-01-14\" --enrich-geo /var/log/auth.log\n";
    std::cout << "  echo \"192.168.1.1\" | " << program_name << "        # From stdin\n";
    std::cout << "  cat ip_list.txt | " << program_name << " --enrich-geo  # Pipe list\n";
    std::cout << "  grep \"Failed\" /var/log/auth.log | " << program_name << " --detect-login\n";
    std::cout << "  " << program_name << " \"/var/log/*.log\"              # Multiple files\n\n";
    std::cout << "Configuration:\n";
    std::cout << "  Config file: ~/.ipdigger/settings.conf\n";
    std::cout << "  Cache dir:   ~/.ipdigger/cache/\n";
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

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
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

            if (files.size() == 1) {
                // Single file - use parallel parsing for large files
                if (actual_threads > 1) {
                    entries = ipdigger::parse_file_parallel(
                        files[0], cache, show_progress, detect_login,
                        search_string, search_regex, actual_threads, config.chunk_size_mb
                    );
                } else {
                    // Single-threaded
                    entries = ipdigger::parse_file(files[0], cache, show_progress, detect_login,
                                                  search_string, search_regex);
                }
            } else {
                // Multiple files - use multi-file parallel parser
                entries = ipdigger::parse_files(files, cache, show_progress, detect_login,
                                               search_string, search_regex);
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

        // Enrich statistics if requested
        if (enable_geo || enable_rdns || enable_abuseipdb || enable_whois || enable_ping || enable_tls || enable_http) {
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
        if (output_geomap) {
            ipdigger::print_stats_geomap(stats, search_active);
        } else if (output_json) {
            ipdigger::print_stats_json(stats, search_active);
        } else {
            ipdigger::print_stats_table(stats, search_active);
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
