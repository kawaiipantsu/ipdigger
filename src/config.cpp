#include "config.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <regex>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

namespace ipdigger {

// Default constructor with sensible defaults
Config::Config() {
    // Output settings - conservative defaults
    default_enrich = false;  // Opt-in for enrichment
    default_json = false;

    // Enrichment settings
    enrich_geo = true;
    enrich_threat = true;
    enrich_rdns = true;
    parallel_requests = 3;
    rdns_threads = 4;

    // Cache settings
    cache_dir = get_config_directory() + "/cache";
    cache_ttl_hours = 24;
    cache_enabled = true;

    // MaxMind settings
    maxmind_db_dir = get_config_directory() + "/maxmind";
    maxmind_account_id = "";
    maxmind_license_key = "";
    maxmind_auto_download = true;

    // AbuseIPDB settings
    abuseipdb_api_key = "";

    config_file_path = get_config_file_path();
}

std::string get_config_directory() {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::string(home) + "/.ipdigger";
}

std::string get_config_file_path() {
    return get_config_directory() + "/settings.conf";
}

std::string create_config_directory() {
    std::string config_dir = get_config_directory();

    // Check if directory exists
    struct stat st;
    if (stat(config_dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        return config_dir;  // Already exists
    }

    // Create directory with 0700 permissions (owner only)
    if (mkdir(config_dir.c_str(), 0700) != 0) {
        std::cerr << "Warning: Failed to create config directory: " << config_dir << "\n";
    }

    // Also create cache subdirectory
    std::string cache_dir = config_dir + "/cache";
    if (stat(cache_dir.c_str(), &st) != 0) {
        if (mkdir(cache_dir.c_str(), 0700) != 0) {
            std::cerr << "Warning: Failed to create cache directory: " << cache_dir << "\n";
        }
    }

    return config_dir;
}

bool create_example_config(const std::string& config_path) {
    // Check if config already exists
    struct stat st;
    if (stat(config_path.c_str(), &st) == 0) {
        return true;  // Already exists
    }

    // Create example config file
    std::ofstream file(config_path);
    if (!file.is_open()) {
        std::cerr << "Warning: Failed to create example config: " << config_path << "\n";
        return false;
    }

    file << "# IPDigger Configuration\n";
    file << "# This file was automatically created. Configure your API keys below.\n\n";
    file << "[output]\n";
    file << "# Default output settings (can be overridden by CLI flags)\n";
    file << "default_json = false          # Enable --output-json by default\n\n";
    file << "[enrichment]\n";
    file << "# Enrichment settings\n";
    file << "parallel_requests = 3        # Max concurrent API requests\n";
    file << "rdns_threads = 4             # Number of threads for reverse DNS lookups\n\n";
    file << "[cache]\n";
    file << "# Cache configuration\n";
    file << "cache_dir = ~/.ipdigger/cache\n";
    file << "cache_ttl_hours = 24         # Cache validity period\n";
    file << "cache_enabled = true         # Enable/disable caching\n\n";
    file << "[maxmind]\n";
    file << "# MaxMind GeoIP database settings (for --enrich-geo)\n";
    file << "# Get free GeoLite2 account at https://www.maxmind.com/en/geolite2/signup\n";
    file << "db_dir = ~/.ipdigger/maxmind\n";
    file << "account_id =                 # Your MaxMind Account ID (for auto-download)\n";
    file << "license_key =                # Your MaxMind License Key (for auto-download)\n";
    file << "auto_download = true         # Auto-download databases if missing\n\n";
    file << "[abuseipdb]\n";
    file << "# AbuseIPDB threat intelligence settings (for --enrich-abuseipdb)\n";
    file << "# Get free API key at https://www.abuseipdb.com/api (1000 requests/day)\n";
    file << "api_key =                    # Required for --enrich-abuseipdb\n";

    file.close();

    // Set permissions to 0600 (owner read/write only) for security
    chmod(config_path.c_str(), 0600);

    return true;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

bool parse_bool(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    return (lower == "true" || lower == "1" || lower == "yes" || lower == "on");
}

std::string expand_home_dir(const std::string& path) {
    if (path.empty() || path[0] != '~') {
        return path;
    }

    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }

    if (path.length() == 1 || path[1] == '/') {
        return std::string(home) + path.substr(1);
    }

    return path;  // ~username not supported, return as-is
}

std::map<std::string, std::map<std::string, std::string>> parse_ini_file(
    const std::string& filepath
) {
    std::map<std::string, std::map<std::string, std::string>> result;
    std::ifstream file(filepath);

    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + filepath);
    }

    std::string current_section;
    std::string line;
    size_t line_num = 0;

    while (std::getline(file, line)) {
        line_num++;

        // Trim whitespace
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // Check for section header [section]
        if (line[0] == '[' && line[line.length()-1] == ']') {
            current_section = line.substr(1, line.length()-2);
            continue;
        }

        // Parse key = value
        size_t equals_pos = line.find('=');
        if (equals_pos == std::string::npos) {
            std::cerr << "Warning: Invalid line " << line_num
                      << " in config file: " << line << "\n";
            continue;
        }

        std::string key = trim(line.substr(0, equals_pos));
        std::string value = trim(line.substr(equals_pos + 1));

        if (current_section.empty()) {
            std::cerr << "Warning: Key outside of section at line "
                      << line_num << "\n";
            continue;
        }

        result[current_section][key] = value;
    }

    return result;
}

std::vector<APIProvider> parse_api_providers(
    const std::map<std::string, std::string>& provider_section
) {
    std::vector<APIProvider> providers;
    std::map<size_t, APIProvider> provider_map;

    // Group by provider number
    std::regex pattern(R"(provider(\d+)_(\w+))");

    for (const auto& [key, value] : provider_section) {
        std::smatch match;
        if (std::regex_match(key, match, pattern)) {
            size_t num = std::stoul(match[1].str());
            std::string attr = match[2].str();

            auto& provider = provider_map[num];

            if (attr == "name") {
                provider.name = value;
            } else if (attr == "type") {
                provider.type = value;
            } else if (attr == "url") {
                provider.url_template = value;
            } else if (attr == "api_key") {
                provider.api_key = value;
            } else if (attr == "enabled") {
                provider.enabled = parse_bool(value);
            } else if (attr == "timeout_ms") {
                try {
                    provider.timeout_ms = std::stoul(value);
                } catch (...) {
                    provider.timeout_ms = 5000;  // Default
                }
            } else if (attr == "rate_limit_ms") {
                try {
                    provider.rate_limit_ms = std::stoul(value);
                } catch (...) {
                    provider.rate_limit_ms = 100;  // Default
                }
            }
        }
    }

    // Convert map to vector, filter enabled providers with API keys
    for (const auto& [num, provider] : provider_map) {
        if (provider.enabled && !provider.api_key.empty() && !provider.url_template.empty()) {
            providers.push_back(provider);
        }
    }

    return providers;
}

Config load_config_from_file(const std::string& config_path) {
    Config config;  // Start with defaults

    try {
        auto ini_data = parse_ini_file(config_path);

        // Parse [output] section
        if (ini_data.count("output")) {
            auto& output = ini_data["output"];
            if (output.count("default_enrich")) {
                config.default_enrich = parse_bool(output["default_enrich"]);
            }
            if (output.count("default_json")) {
                config.default_json = parse_bool(output["default_json"]);
            }
        }

        // Parse [enrichment] section
        if (ini_data.count("enrichment")) {
            auto& enrich = ini_data["enrichment"];
            if (enrich.count("enrich_geo")) {
                config.enrich_geo = parse_bool(enrich["enrich_geo"]);
            }
            if (enrich.count("enrich_threat")) {
                config.enrich_threat = parse_bool(enrich["enrich_threat"]);
            }
            if (enrich.count("enrich_rdns")) {
                config.enrich_rdns = parse_bool(enrich["enrich_rdns"]);
            }
            if (enrich.count("parallel_requests")) {
                try {
                    config.parallel_requests = std::stoul(enrich["parallel_requests"]);
                } catch (...) {
                    // Keep default
                }
            }
            if (enrich.count("rdns_threads")) {
                try {
                    config.rdns_threads = std::stoul(enrich["rdns_threads"]);
                    if (config.rdns_threads == 0) config.rdns_threads = 1;  // At least 1 thread
                } catch (...) {
                    // Keep default
                }
            }
        }

        // Parse [cache] section
        if (ini_data.count("cache")) {
            auto& cache = ini_data["cache"];
            if (cache.count("cache_dir")) {
                config.cache_dir = expand_home_dir(cache["cache_dir"]);
            }
            if (cache.count("cache_ttl_hours")) {
                try {
                    config.cache_ttl_hours = std::stoul(cache["cache_ttl_hours"]);
                } catch (...) {
                    // Keep default
                }
            }
            if (cache.count("cache_enabled")) {
                config.cache_enabled = parse_bool(cache["cache_enabled"]);
            }
        }

        // Parse [maxmind] section
        if (ini_data.count("maxmind")) {
            auto& maxmind = ini_data["maxmind"];
            if (maxmind.count("db_dir")) {
                config.maxmind_db_dir = expand_home_dir(maxmind["db_dir"]);
            }
            if (maxmind.count("account_id")) {
                config.maxmind_account_id = maxmind["account_id"];
            }
            if (maxmind.count("license_key")) {
                config.maxmind_license_key = maxmind["license_key"];
            }
            if (maxmind.count("auto_download")) {
                config.maxmind_auto_download = parse_bool(maxmind["auto_download"]);
            }
        }

        // Parse [abuseipdb] section
        if (ini_data.count("abuseipdb")) {
            auto& abuseipdb = ini_data["abuseipdb"];
            if (abuseipdb.count("api_key")) {
                config.abuseipdb_api_key = abuseipdb["api_key"];
            }
        }

        // Parse [api_providers] section
        if (ini_data.count("api_providers")) {
            config.providers = parse_api_providers(ini_data["api_providers"]);
        }

    } catch (const std::exception& e) {
        std::cerr << "Warning: Error parsing config file: " << e.what() << "\n";
        // Return config with defaults
    }

    return config;
}

Config load_config() {
    Config config;  // Start with defaults

    // Ensure config directory exists
    create_config_directory();

    // Get config file path
    std::string config_path = get_config_file_path();

    // Check if config file exists
    struct stat st;
    if (stat(config_path.c_str(), &st) == 0) {
        // Config exists, load it
        try {
            config = load_config_from_file(config_path);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to load config from "
                      << config_path << ": " << e.what() << "\n";
            // Continue with defaults
        }
    } else {
        // Config doesn't exist, create example
        if (create_example_config(config_path)) {
            std::cerr << "Created example config at: " << config_path << "\n";
            std::cerr << "Configure your API keys to enable enrichment.\n";
        }
    }

    // Override with environment variables
    if (const char* env_enrich = std::getenv("IPDIGGER_ENRICH")) {
        config.default_enrich = parse_bool(env_enrich);
    }
    if (const char* env_cache_dir = std::getenv("IPDIGGER_CACHE_DIR")) {
        config.cache_dir = expand_home_dir(env_cache_dir);
    }

    // Ensure cache directory exists if caching is enabled
    if (config.cache_enabled) {
        struct stat st;
        if (stat(config.cache_dir.c_str(), &st) != 0) {
            if (mkdir(config.cache_dir.c_str(), 0700) != 0) {
                // Failed to create, disable cache
                config.cache_enabled = false;
            }
        }
    }

    return config;
}

} // namespace ipdigger
