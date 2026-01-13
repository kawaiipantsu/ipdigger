#include "enrichment.h"
#include "json.hpp"  // nlohmann/json
#include <curl/curl.h>
#include <openssl/sha.h>
#include <maxminddb.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <algorithm>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <vector>
#include <queue>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>
#include <zlib.h>
#include <tar.h>

namespace ipdigger {

// CURL write callback
static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

bool file_exists(const std::string& filepath) {
    struct stat st;
    return (stat(filepath.c_str(), &st) == 0);
}

bool create_directory_recursive(const std::string& path) {
    // Check if already exists
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        return true;
    }

    // Create parent directories first
    size_t pos = path.find_last_of('/');
    if (pos != std::string::npos) {
        std::string parent = path.substr(0, pos);
        if (!create_directory_recursive(parent)) {
            return false;
        }
    }

    // Create this directory
    return (mkdir(path.c_str(), 0700) == 0 || errno == EEXIST);
}

std::string get_cache_filename(const std::string& ip_address) {
    // Hash the IP address using SHA256 for privacy
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(ip_address.c_str()),
           ip_address.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string replace_url_placeholders(
    const std::string& url_template,
    const std::string& ip_address,
    const std::string& api_key
) {
    std::string url = url_template;

    // Replace {ip} placeholder
    size_t pos = url.find("{ip}");
    while (pos != std::string::npos) {
        url.replace(pos, 4, ip_address);
        pos = url.find("{ip}", pos + ip_address.length());
    }

    // Replace {api_key} placeholder
    pos = url.find("{api_key}");
    while (pos != std::string::npos) {
        url.replace(pos, 9, api_key);
        pos = url.find("{api_key}", pos + api_key.length());
    }

    return url;
}

std::string http_get(const std::string& url, size_t timeout_ms) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response_data;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);  // Security
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);  // Security
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "IPDigger/1.0");

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        std::string error = std::string("CURL request failed: ") + curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        throw std::runtime_error(error);
    }

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    if (response_code != 200) {
        throw std::runtime_error(
            "HTTP request failed with code: " + std::to_string(response_code)
        );
    }

    return response_data;
}

std::map<std::string, std::string> parse_api_response(
    const APIProvider& provider,
    const std::string& response_json
) {
    std::map<std::string, std::string> fields;

    try {
        nlohmann::json json = nlohmann::json::parse(response_json);

        if (provider.type == "geo") {
            // Extract common geo fields (IPInfo.io format and similar)
            if (json.contains("country")) {
                fields["country"] = json["country"].get<std::string>();
            }
            if (json.contains("city")) {
                fields["city"] = json["city"].get<std::string>();
            }
            if (json.contains("region")) {
                fields["region"] = json["region"].get<std::string>();
            }
            if (json.contains("org")) {
                fields["org"] = json["org"].get<std::string>();
            }
            if (json.contains("asn")) {
                auto asn_obj = json["asn"];
                if (asn_obj.is_object() && asn_obj.contains("asn")) {
                    fields["asn"] = "AS" + asn_obj["asn"].get<std::string>();
                } else if (asn_obj.is_string()) {
                    fields["asn"] = asn_obj.get<std::string>();
                }
            }
            if (json.contains("timezone")) {
                fields["timezone"] = json["timezone"].get<std::string>();
            }

        } else if (provider.type == "threat") {
            // Extract common threat fields (AbuseIPDB format and similar)
            if (json.contains("data")) {
                auto data = json["data"];
                if (data.contains("abuseConfidenceScore")) {
                    fields["abuse_score"] = std::to_string(
                        data["abuseConfidenceScore"].get<int>()
                    );
                }
                if (data.contains("isWhitelisted")) {
                    fields["whitelisted"] = data["isWhitelisted"].get<bool>()
                        ? "true" : "false";
                }
                if (data.contains("usageType")) {
                    fields["usage_type"] = data["usageType"].get<std::string>();
                }
                if (data.contains("totalReports")) {
                    fields["total_reports"] = std::to_string(
                        data["totalReports"].get<int>()
                    );
                }
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to parse API response: " << e.what() << "\n";
    }

    return fields;
}

std::shared_ptr<EnrichmentData> load_from_cache(
    const std::string& ip_address,
    const std::string& cache_dir,
    size_t cache_ttl_hours
) {
    std::string cache_file = cache_dir + "/" + get_cache_filename(ip_address) + ".json";

    if (!file_exists(cache_file)) {
        return nullptr;
    }

    // Check file age
    struct stat st;
    if (stat(cache_file.c_str(), &st) != 0) {
        return nullptr;
    }

    time_t now = std::time(nullptr);
    time_t age_hours = (now - st.st_mtime) / 3600;

    if (age_hours > static_cast<time_t>(cache_ttl_hours)) {
        return nullptr;  // Cache expired
    }

    // Read and parse cache file
    std::ifstream file(cache_file);
    if (!file.is_open()) {
        return nullptr;
    }

    try {
        std::string json_str((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());

        nlohmann::json json = nlohmann::json::parse(json_str);

        auto data = std::make_shared<EnrichmentData>();
        data->ip_address = json["ip_address"].get<std::string>();
        data->cached_at = json["cached_at"].get<time_t>();
        data->from_cache = true;

        for (auto& [key, value] : json["data"].items()) {
            data->data[key] = value.get<std::string>();
        }

        return data;

    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to load cache for " << ip_address
                  << ": " << e.what() << "\n";
        return nullptr;
    }
}

void save_to_cache(const EnrichmentData& data, const std::string& cache_dir) {
    // Ensure cache directory exists
    if (!create_directory_recursive(cache_dir)) {
        std::cerr << "Warning: Failed to create cache directory: " << cache_dir << "\n";
        return;
    }

    std::string cache_file = cache_dir + "/" + get_cache_filename(data.ip_address) + ".json";

    try {
        nlohmann::json json;
        json["ip_address"] = data.ip_address;
        json["cached_at"] = std::time(nullptr);
        json["data"] = data.data;

        std::ofstream file(cache_file);
        if (file.is_open()) {
            file << json.dump(2);  // Pretty print with 2-space indent
        } else {
            std::cerr << "Warning: Failed to write cache file: " << cache_file << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to save cache for " << data.ip_address
                  << ": " << e.what() << "\n";
    }
}

EnrichmentData fetch_enrichment(
    const std::string& ip_address,
    const std::vector<APIProvider>& providers,
    const Config& config
) {
    EnrichmentData result;
    result.ip_address = ip_address;
    result.from_cache = false;

    // Try cache first
    if (config.cache_enabled) {
        auto cached = load_from_cache(
            ip_address,
            config.cache_dir,
            config.cache_ttl_hours
        );
        if (cached) {
            return *cached;
        }
    }

    // Query providers
    for (const auto& provider : providers) {
        if (!provider.enabled) continue;

        try {
            // Replace placeholders in URL template
            std::string url = replace_url_placeholders(
                provider.url_template,
                ip_address,
                provider.api_key
            );

            // Make HTTP request
            std::string response = http_get(url, provider.timeout_ms);

            // Parse response
            auto fields = parse_api_response(provider, response);

            // Merge into result
            for (const auto& [key, value] : fields) {
                result.data[key] = value;
            }

            // Rate limiting
            if (provider.rate_limit_ms > 0) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(provider.rate_limit_ms)
                );
            }

        } catch (const std::exception& e) {
            std::cerr << "Warning: Provider " << provider.name
                      << " failed for " << ip_address << ": "
                      << e.what() << "\n";
            // Continue with next provider
        }
    }

    // Cache result if we got any data
    if (!result.data.empty() && config.cache_enabled) {
        result.cached_at = std::time(nullptr);
        save_to_cache(result, config.cache_dir);
    }

    return result;
}

void enrich_entries(std::vector<IPEntry>& entries, const Config& config) {
    if (config.providers.empty()) {
        return;  // No providers configured
    }

    // Extract unique IPs to avoid duplicate API calls
    std::set<std::string> unique_ips;
    for (const auto& entry : entries) {
        unique_ips.insert(entry.ip_address);
    }

    // Fetch enrichment for each unique IP
    std::map<std::string, std::shared_ptr<EnrichmentData>> enrichment_map;

    for (const auto& ip : unique_ips) {
        try {
            EnrichmentData data = fetch_enrichment(ip, config.providers, config);
            enrichment_map[ip] = std::make_shared<EnrichmentData>(data);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to enrich " << ip << ": "
                      << e.what() << "\n";
            // Continue with other IPs
        }
    }

    // Attach enrichment data to entries
    for (auto& entry : entries) {
        if (enrichment_map.count(entry.ip_address)) {
            entry.enrichment = enrichment_map[entry.ip_address];
        }
    }
}

void enrich_statistics(std::map<std::string, IPStats>& stats, const Config& config) {
    if (config.providers.empty()) {
        return;  // No providers configured
    }

    // Fetch enrichment for each unique IP
    for (auto& [ip, stat] : stats) {
        try {
            EnrichmentData data = fetch_enrichment(ip, config.providers, config);
            stat.enrichment = std::make_shared<EnrichmentData>(data);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to enrich " << ip << ": "
                      << e.what() << "\n";
            // Continue with other IPs
        }
    }
}

// ===== Reverse DNS Functions =====

// Helper function to display progress bar (thread-safe)
void display_progress(size_t completed, size_t total, bool show_progress, std::mutex& progress_mutex) {
    if (!show_progress) return;

    std::lock_guard<std::mutex> lock(progress_mutex);

    int bar_width = 40;
    float progress = static_cast<float>(completed) / total;
    int pos = static_cast<int>(bar_width * progress);

    std::cerr << "\rPerforming reverse DNS lookups... [";
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cerr << "=";
        else if (i == pos) std::cerr << ">";
        else std::cerr << " ";
    }
    std::cerr << "] " << static_cast<int>(progress * 100) << "% ("
              << completed << "/" << total << " IPs)";
    std::cerr.flush();

    if (completed == total) {
        std::cerr << "\n";
    }
}

std::string reverse_dns_lookup(const std::string& ip_address) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    char host[NI_MAXHOST];

    // Try IPv4 first
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_address.c_str(), &sa.sin_addr) == 1) {
        // Valid IPv4 address
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, 0) == 0) {
            return std::string(host);
        }
    } else {
        // Try IPv6
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;

        if (inet_pton(AF_INET6, ip_address.c_str(), &sa6.sin6_addr) == 1) {
            // Valid IPv6 address
            if (getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), host, sizeof(host), nullptr, 0, 0) == 0) {
                return std::string(host);
            }
        }
    }

    return "";  // Lookup failed
}

void enrich_rdns(std::vector<IPEntry>& entries, const Config& config) {
    // Extract unique IPs
    std::set<std::string> unique_ips;
    for (const auto& entry : entries) {
        unique_ips.insert(entry.ip_address);
    }

    if (unique_ips.empty()) return;

    // Convert to vector for thread processing
    std::vector<std::string> ip_list(unique_ips.begin(), unique_ips.end());
    size_t total_ips = ip_list.size();

    // Thread-safe data structures
    std::map<std::string, std::string> rdns_map;
    std::mutex map_mutex;
    std::mutex progress_mutex;
    std::atomic<size_t> completed(0);
    std::atomic<size_t> current_index(0);

    // Determine if we should show progress (not in JSON mode)
    bool show_progress = true;  // Can be passed from caller if needed

    // Worker function
    auto worker = [&]() {
        while (true) {
            size_t index = current_index.fetch_add(1);
            if (index >= total_ips) break;

            const std::string& ip = ip_list[index];
            try {
                std::string hostname = reverse_dns_lookup(ip);
                // Only add if hostname is not empty and not the same as the IP
                if (!hostname.empty() && hostname != ip) {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    rdns_map[ip] = hostname;
                }
            } catch (const std::exception& e) {
                // Silently ignore errors during threaded operation
            }

            // Update progress
            size_t done = completed.fetch_add(1) + 1;
            display_progress(done, total_ips, show_progress, progress_mutex);
        }
    };

    // Create thread pool
    size_t num_threads = std::min(config.rdns_threads, total_ips);
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    // Start initial progress
    display_progress(0, total_ips, show_progress, progress_mutex);

    // Launch threads
    for (size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // Attach rDNS data to entries
    for (auto& entry : entries) {
        if (rdns_map.count(entry.ip_address)) {
            if (!entry.enrichment) {
                entry.enrichment = std::make_shared<EnrichmentData>();
                entry.enrichment->ip_address = entry.ip_address;
            }
            entry.enrichment->data["rdns"] = rdns_map[entry.ip_address];
        }
    }
}

void enrich_rdns_stats(std::map<std::string, IPStats>& stats, const Config& config) {
    if (stats.empty()) return;

    // Extract IPs from stats
    std::vector<std::string> ip_list;
    for (const auto& [ip, stat] : stats) {
        ip_list.push_back(ip);
    }

    size_t total_ips = ip_list.size();

    // Thread-safe data structures
    std::map<std::string, std::string> rdns_map;
    std::mutex map_mutex;
    std::mutex progress_mutex;
    std::atomic<size_t> completed(0);
    std::atomic<size_t> current_index(0);

    bool show_progress = true;

    // Worker function
    auto worker = [&]() {
        while (true) {
            size_t index = current_index.fetch_add(1);
            if (index >= total_ips) break;

            const std::string& ip = ip_list[index];
            try {
                std::string hostname = reverse_dns_lookup(ip);
                // Only add if hostname is not empty and not the same as the IP
                if (!hostname.empty() && hostname != ip) {
                    std::lock_guard<std::mutex> lock(map_mutex);
                    rdns_map[ip] = hostname;
                }
            } catch (const std::exception& e) {
                // Silently ignore errors during threaded operation
            }

            // Update progress
            size_t done = completed.fetch_add(1) + 1;
            display_progress(done, total_ips, show_progress, progress_mutex);
        }
    };

    // Create thread pool
    size_t num_threads = std::min(config.rdns_threads, total_ips);
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    // Start initial progress
    display_progress(0, total_ips, show_progress, progress_mutex);

    // Launch threads
    for (size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // Attach rDNS data to stats
    for (auto& [ip, stat] : stats) {
        if (rdns_map.count(ip)) {
            if (!stat.enrichment) {
                stat.enrichment = std::make_shared<EnrichmentData>();
                stat.enrichment->ip_address = ip;
            }
            stat.enrichment->data["rdns"] = rdns_map[ip];
        }
    }
}

// ===== MaxMind Functions =====

std::map<std::string, std::string> find_maxmind_databases() {
    std::map<std::string, std::string> databases;

    // Known system locations for MaxMind databases
    std::vector<std::string> search_paths = {
        "/usr/share/GeoIP/",
        "/usr/local/share/GeoIP/",
        "/var/lib/GeoIP/",
        "/opt/GeoIP/",
        std::string(getenv("HOME") ? getenv("HOME") : "") + "/.ipdigger/maxmind/"
    };

    std::vector<std::string> db_names = {
        "GeoLite2-City.mmdb",
        "GeoLite2-Country.mmdb",
        "GeoLite2-ASN.mmdb",
        "GeoIP2-City.mmdb",
        "GeoIP2-Country.mmdb",
        "GeoIP2-ASN.mmdb"
    };

    for (const auto& path : search_paths) {
        for (const auto& db_name : db_names) {
            std::string full_path = path + db_name;
            if (file_exists(full_path)) {
                if (db_name.find("City") != std::string::npos) {
                    databases["city"] = full_path;
                } else if (db_name.find("Country") != std::string::npos) {
                    databases["country"] = full_path;
                } else if (db_name.find("ASN") != std::string::npos) {
                    databases["asn"] = full_path;
                }
            }
        }
    }

    return databases;
}

bool download_maxmind_databases(const std::string& license_key, const std::string& db_dir) {
    if (license_key.empty()) {
        std::cerr << "Error: MaxMind license key not configured\n";
        std::cerr << "       Get a free key at https://www.maxmind.com/en/geolite2/signup\n";
        return false;
    }

    // Create database directory
    if (!create_directory_recursive(db_dir)) {
        std::cerr << "Error: Failed to create MaxMind database directory: " << db_dir << "\n";
        return false;
    }

    std::cerr << "Downloading MaxMind GeoLite2 databases...\n";

    // Download GeoLite2-City, GeoLite2-Country, and GeoLite2-ASN
    std::vector<std::string> editions = {"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"};

    for (const auto& edition : editions) {
        try {
            std::string url = "https://download.maxmind.com/app/geoip_download?" +
                             std::string("edition_id=") + edition +
                             "&license_key=" + license_key +
                             "&suffix=tar.gz";

            std::string tar_file = db_dir + "/" + edition + ".tar.gz";

            // Download using curl
            CURL* curl = curl_easy_init();
            if (!curl) continue;

            FILE* fp = fopen(tar_file.c_str(), "wb");
            if (!fp) {
                curl_easy_cleanup(curl);
                continue;
            }

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);  // 5 minutes

            CURLcode res = curl_easy_perform(curl);
            fclose(fp);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK) {
                std::cerr << "Warning: Failed to download " << edition << "\n";
                continue;
            }

            // Extract .mmdb file from tar.gz
            std::string extract_cmd = "cd " + db_dir + " && " +
                                     "tar -xzf " + edition + ".tar.gz --wildcards '*.mmdb' --strip-components=1 && " +
                                     "rm " + edition + ".tar.gz";

            if (system(extract_cmd.c_str()) == 0) {
                std::cerr << "Downloaded and extracted " << edition << ".mmdb\n";
            } else {
                std::cerr << "Warning: Failed to extract " << edition << "\n";
            }

        } catch (const std::exception& e) {
            std::cerr << "Warning: Error downloading " << edition << ": " << e.what() << "\n";
        }
    }

    return true;
}

std::map<std::string, std::string> maxmind_lookup(
    const std::string& ip_address,
    const std::string& db_path
) {
    std::map<std::string, std::string> result;

    MMDB_s mmdb;
    int status = MMDB_open(db_path.c_str(), MMDB_MODE_MMAP, &mmdb);

    if (status != MMDB_SUCCESS) {
        return result;  // Failed to open database
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s lookup_result = MMDB_lookup_string(&mmdb, ip_address.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !lookup_result.found_entry) {
        MMDB_close(&mmdb);
        return result;  // Lookup failed
    }

    MMDB_entry_data_s entry_data;

    // Extract country code
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            result["country_code"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
    }

    // Extract country name
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            result["country"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
    }

    // Extract city name (only in City database)
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "city", "names", "en", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            result["city"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
    }

    // Extract AS Number
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32) {
            result["asn"] = "AS" + std::to_string(entry_data.uint32);
        }
    }

    // Extract AS Organization
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "autonomous_system_organization", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            result["org"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
    }

    MMDB_close(&mmdb);
    return result;
}

void enrich_geoip(std::vector<IPEntry>& entries, const Config& config) {
    // Find MaxMind databases
    auto databases = find_maxmind_databases();

    // If no databases found and auto-download enabled, try to download
    if (databases.empty() && config.maxmind_auto_download && !config.maxmind_license_key.empty()) {
        std::cerr << "MaxMind databases not found. Attempting download...\n";
        download_maxmind_databases(config.maxmind_license_key, config.maxmind_db_dir);
        databases = find_maxmind_databases();
    }

    if (databases.empty()) {
        std::cerr << "Warning: No MaxMind databases found. GeoIP enrichment unavailable.\n";
        std::cerr << "         Configure license_key in ~/.ipdigger/settings.conf or\n";
        std::cerr << "         install databases in /usr/share/GeoIP/\n";
        return;
    }

    // Prefer City database (has more data)
    std::string db_path = databases.count("city") ? databases["city"] : databases["country"];
    std::string asn_db_path = databases.count("asn") ? databases["asn"] : "";

    // Extract unique IPs
    std::set<std::string> unique_ips;
    for (const auto& entry : entries) {
        unique_ips.insert(entry.ip_address);
    }

    // Perform GeoIP lookup for each unique IP
    std::map<std::string, std::map<std::string, std::string>> geo_map;

    for (const auto& ip : unique_ips) {
        try {
            // Query City/Country database
            auto geo_data = maxmind_lookup(ip, db_path);

            // Also query ASN database if available
            if (!asn_db_path.empty()) {
                auto asn_data = maxmind_lookup(ip, asn_db_path);
                // Merge ASN data into geo_data
                for (const auto& [key, value] : asn_data) {
                    geo_data[key] = value;
                }
            }

            if (!geo_data.empty()) {
                geo_map[ip] = geo_data;
            }
        } catch (const std::exception& e) {
            std::cerr << "Warning: GeoIP lookup failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }

    // Attach GeoIP data to entries
    for (auto& entry : entries) {
        if (geo_map.count(entry.ip_address)) {
            if (!entry.enrichment) {
                entry.enrichment = std::make_shared<EnrichmentData>();
                entry.enrichment->ip_address = entry.ip_address;
            }
            for (const auto& [key, value] : geo_map[entry.ip_address]) {
                entry.enrichment->data[key] = value;
            }
        }
    }
}

void enrich_geoip_stats(std::map<std::string, IPStats>& stats, const Config& config) {
    // Find MaxMind databases
    auto databases = find_maxmind_databases();

    // If no databases found and auto-download enabled, try to download
    if (databases.empty() && config.maxmind_auto_download && !config.maxmind_license_key.empty()) {
        std::cerr << "MaxMind databases not found. Attempting download...\n";
        download_maxmind_databases(config.maxmind_license_key, config.maxmind_db_dir);
        databases = find_maxmind_databases();
    }

    if (databases.empty()) {
        std::cerr << "Warning: No MaxMind databases found. GeoIP enrichment unavailable.\n";
        return;
    }

    // Prefer City database
    std::string db_path = databases.count("city") ? databases["city"] : databases["country"];
    std::string asn_db_path = databases.count("asn") ? databases["asn"] : "";

    for (auto& [ip, stat] : stats) {
        try {
            // Query City/Country database
            auto geo_data = maxmind_lookup(ip, db_path);

            // Also query ASN database if available
            if (!asn_db_path.empty()) {
                auto asn_data = maxmind_lookup(ip, asn_db_path);
                // Merge ASN data into geo_data
                for (const auto& [key, value] : asn_data) {
                    geo_data[key] = value;
                }
            }

            if (!geo_data.empty()) {
                if (!stat.enrichment) {
                    stat.enrichment = std::make_shared<EnrichmentData>();
                    stat.enrichment->ip_address = ip;
                }
                for (const auto& [key, value] : geo_data) {
                    stat.enrichment->data[key] = value;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Warning: GeoIP lookup failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }
}

} // namespace ipdigger
