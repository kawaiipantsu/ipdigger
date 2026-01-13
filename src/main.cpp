#include <iostream>
#include <string>
#include <cstring>
#include <set>
#include <algorithm>
#include "ipdigger.h"
#include "config.h"
#include "enrichment.h"

void print_usage(const char* program_name) {
    std::cout << "\n";
    std::cout << "     ___________ ____________\n";
    std::cout << "    |           )._______.-'\n";
    std::cout << "    `----------'\n";
    std::cout << "\n";
    std::cout << "       IP Digger v" << ipdigger::get_version() << "\n";
    std::cout << "  Your swiss armyknife tool for IP addresses\n";
    std::cout << "\n";
    std::cout << "Usage: " << program_name << " [OPTIONS] <filename>\n\n";
    std::cout << "Options:\n";
    std::cout << "  --output-json  Output in JSON format\n";
    std::cout << "  --enrich       Enrich IPs with geolocation and threat data (requires config)\n";
    std::cout << "  --enrich-geo   Enrich IPs with geolocation data (MaxMind)\n";
    std::cout << "  --enrich-rdns  Enrich IPs with reverse DNS lookups\n";
    std::cout << "  --no-enrich    Disable enrichment (overrides config default)\n";
    std::cout << "  --top-10       Show only top 10 IPs by count\n";
    std::cout << "  --top-20       Show only top 20 IPs by count\n";
    std::cout << "  --top-50       Show only top 50 IPs by count\n";
    std::cout << "  --top-100      Show only top 100 IPs by count\n";
    std::cout << "  --help         Display this help message\n";
    std::cout << "  --version      Display version information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " /var/log/nginx/access.log\n";
    std::cout << "  " << program_name << " --enrich-geo /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-rdns /var/log/auth.log\n";
    std::cout << "  " << program_name << " --enrich-geo --enrich-rdns /var/log/auth.log\n";
    std::cout << "  " << program_name << " --top-10 --enrich-geo /var/log/auth.log\n";
    std::cout << "  " << program_name << " --top-20 --enrich-rdns --output-json \"*.log\"\n";
    std::cout << "  " << program_name << " \"/var/log/*.log\"              # Multiple files\n";
    std::cout << "  " << program_name << " --output-json /var/log/auth.log\n\n";
    std::cout << "Configuration:\n";
    std::cout << "  Config file: ~/.ipdigger/settings.conf\n";
    std::cout << "  Cache dir:   ~/.ipdigger/cache/\n";
}

void print_version() {
    std::cout << "\n";
    std::cout << "     ___________ ____________\n";
    std::cout << "    |           )._______.-'\n";
    std::cout << "    `----------'\n";
    std::cout << "\n";
    std::cout << "       IP Digger v" << ipdigger::get_version() << "\n";
    std::cout << "  Your swiss armyknife tool for IP addresses\n";
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

    // Parse command line arguments (CLI overrides config)
    bool output_json = config.default_json;
    bool enable_enrich = config.default_enrich;
    bool enable_geo = false;
    bool enable_rdns = false;
    size_t top_n = 0;  // 0 means show all
    std::string filename;

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
        } else if (arg == "--enrich") {
            enable_enrich = true;
        } else if (arg == "--enrich-geo") {
            enable_geo = true;
        } else if (arg == "--enrich-rdns") {
            enable_rdns = true;
        } else if (arg == "--no-enrich") {
            enable_enrich = false;
            enable_geo = false;
            enable_rdns = false;
        } else if (arg == "--top-10") {
            top_n = 10;
        } else if (arg == "--top-20") {
            top_n = 20;
        } else if (arg == "--top-50") {
            top_n = 50;
        } else if (arg == "--top-100") {
            top_n = 100;
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

    // Validate input
    if (filename.empty()) {
        std::cerr << "Error: No filename specified\n";
        print_usage(argv[0]);
        return 1;
    }

    try {
        // Expand glob pattern to get list of files
        auto files = ipdigger::expand_glob(filename);

        if (files.empty()) {
            std::cerr << "Error: No files matched pattern: " << filename << "\n";
            return 1;
        }

        // Parse all files (show progress if not in JSON mode)
        bool show_progress = !output_json;
        std::vector<ipdigger::IPEntry> entries;
        if (files.size() == 1) {
            // Single file - use direct parsing for better error messages
            entries = ipdigger::parse_file(files[0], show_progress);
        } else {
            // Multiple files - use multi-file parser with error handling
            entries = ipdigger::parse_files(files, show_progress);
        }

        // Apply top N filtering if requested
        std::set<std::string> top_ips;
        if (top_n > 0) {
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
                if (count >= top_n) break;
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
        if (enable_enrich || enable_geo || enable_rdns) {
            // Apply enrichments
            if (enable_enrich && !config.providers.empty()) {
                if (!output_json) std::cout << "Enriching with API data...\n";
                ipdigger::enrich_statistics(stats, config);
            } else if (enable_enrich) {
                std::cerr << "Warning: --enrich specified but no API providers configured\n";
                std::cerr << "         Configure providers in " << config.config_file_path << "\n";
            }

            if (enable_geo) {
                if (!output_json) std::cout << "Enriching with GeoIP data...\n";
                ipdigger::enrich_geoip_stats(stats, config);
            }

            if (enable_rdns) {
                ipdigger::enrich_rdns_stats(stats, config);
            }
        }

        // Display results (always use statistics output)
        if (output_json) {
            ipdigger::print_stats_json(stats);
        } else {
            ipdigger::print_stats_table(stats);
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
