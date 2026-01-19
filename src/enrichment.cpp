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
#include <unistd.h>
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

bool download_maxmind_databases(
    const std::string& account_id,
    const std::string& license_key,
    const std::string& db_dir
) {
    if (account_id.empty() || license_key.empty()) {
        std::cerr << "Error: MaxMind account_id and license_key not configured\n";
        std::cerr << "       Get a free account at https://www.maxmind.com/en/geolite2/signup\n";
        std::cerr << "       Configure both account_id and license_key in [maxmind] section\n";
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
            // MaxMind requires both account_id and license_key
            std::string url = "https://download.maxmind.com/geoip/databases/" + edition +
                             "/download?suffix=tar.gz";

            // Use HTTP Basic Auth with account_id:license_key
            std::string auth = account_id + ":" + license_key;

            std::string tar_file = db_dir + "/" + edition + ".tar.gz";

            // Download using curl with HTTP Basic Auth
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
            curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());  // HTTP Basic Auth
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

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
            result["cc"] = std::string(entry_data.utf8_string, entry_data.data_size);
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

    // Extract latitude (only in City database)
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "location", "latitude", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
            result["latitude"] = std::to_string(entry_data.double_value);
        }
    }

    // Extract longitude (only in City database)
    if (MMDB_get_value(&lookup_result.entry, &entry_data, "location", "longitude", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
            result["longitude"] = std::to_string(entry_data.double_value);
        }
    }

    MMDB_close(&mmdb);
    return result;
}

void enrich_geoip(std::vector<IPEntry>& entries, const Config& config) {
    // Find MaxMind databases
    auto databases = find_maxmind_databases();

    // If no databases found and auto-download enabled, try to download
    if (databases.empty() && config.maxmind_auto_download &&
        !config.maxmind_account_id.empty() && !config.maxmind_license_key.empty()) {
        std::cerr << "MaxMind databases not found. Attempting download...\n";
        download_maxmind_databases(config.maxmind_account_id, config.maxmind_license_key, config.maxmind_db_dir);
        databases = find_maxmind_databases();
    }

    if (databases.empty()) {
        std::cerr << "Warning: No MaxMind databases found. GeoIP enrichment unavailable.\n";
        std::cerr << "         Configure account_id and license_key in ~/.ipdigger/settings.conf or\n";
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
    if (databases.empty() && config.maxmind_auto_download &&
        !config.maxmind_account_id.empty() && !config.maxmind_license_key.empty()) {
        std::cerr << "MaxMind databases not found. Attempting download...\n";
        download_maxmind_databases(config.maxmind_account_id, config.maxmind_license_key, config.maxmind_db_dir);
        databases = find_maxmind_databases();
    }

    if (databases.empty()) {
        std::cerr << "Warning: No MaxMind databases found. GeoIP enrichment unavailable.\n";
        std::cerr << "         Configure account_id and license_key in ~/.ipdigger/settings.conf\n";
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

std::string http_get_with_headers(
    const std::string& url,
    const std::map<std::string, std::string>& headers,
    size_t timeout_ms
) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response_data;

    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "IPDigger/1.1");

    // Add custom headers
    struct curl_slist* header_list = nullptr;
    for (const auto& [key, value] : headers) {
        std::string header = key + ": " + value;
        header_list = curl_slist_append(header_list, header.c_str());
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    // Perform request
    CURLcode res = curl_easy_perform(curl);

    // Clean up
    if (header_list) {
        curl_slist_free_all(header_list);
    }
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("CURL request failed: ") + curl_easy_strerror(res));
    }

    return response_data;
}

std::map<std::string, std::string> abuseipdb_lookup(
    const std::string& ip_address,
    const std::string& api_key
) {
    std::map<std::string, std::string> result;

    if (api_key.empty()) {
        return result;
    }

    try {
        // Build AbuseIPDB API URL
        std::string url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip_address + "&maxAgeInDays=90&verbose";

        // Set up headers with API key
        std::map<std::string, std::string> headers;
        headers["Key"] = api_key;
        headers["Accept"] = "application/json";

        // Make request with 10 second timeout
        std::string response = http_get_with_headers(url, headers, 10000);

        // Parse JSON response
        auto json_data = nlohmann::json::parse(response);

        // Extract data from response
        if (json_data.contains("data")) {
            auto& data = json_data["data"];

            // Extract abuseConfidenceScore
            if (data.contains("abuseConfidenceScore")) {
                result["abuseScore"] = std::to_string(data["abuseConfidenceScore"].get<int>());
            }

            // Extract usageType
            if (data.contains("usageType") && !data["usageType"].is_null()) {
                result["usageType"] = data["usageType"].get<std::string>();
            }

            // Extract totalReports
            if (data.contains("totalReports")) {
                result["totalReports"] = std::to_string(data["totalReports"].get<int>());
            }

            // Extract ISP
            if (data.contains("isp") && !data["isp"].is_null()) {
                result["isp"] = data["isp"].get<std::string>();
            }

            // Extract isTor
            if (data.contains("isTor")) {
                result["isTor"] = data["isTor"].get<bool>() ? "Yes" : "No";
            }
        }
    } catch (const std::exception& e) {
        // Silently fail - don't pollute output
        // Errors will be logged in the calling function
    }

    return result;
}

void enrich_abuseipdb_stats(std::map<std::string, IPStats>& stats, const Config& config) {
    if (config.abuseipdb_api_key.empty()) {
        std::cerr << "Warning: AbuseIPDB API key not configured\n";
        std::cerr << "         Set api_key in [abuseipdb] section of " << config.config_file_path << "\n";
        return;
    }

    // Collect all IPs that need enrichment
    std::vector<std::string> ips_to_enrich;
    for (const auto& [ip, stat] : stats) {
        // Check if already enriched with AbuseIPDB data
        bool has_abuseipdb = false;
        if (stat.enrichment) {
            has_abuseipdb = stat.enrichment->data.count("abuseScore") > 0;
        }
        if (!has_abuseipdb) {
            ips_to_enrich.push_back(ip);
        }
    }

    if (ips_to_enrich.empty()) {
        return;
    }

    std::cout << "Enriching with AbuseIPDB data...\n";

    // Process IPs with progress bar
    size_t completed = 0;
    size_t total = ips_to_enrich.size();
    int bar_width = 40;
    auto start_time = std::chrono::steady_clock::now();

    for (const auto& ip : ips_to_enrich) {
        try {
            auto abuse_data = abuseipdb_lookup(ip, config.abuseipdb_api_key);

            if (!abuse_data.empty()) {
                auto& stat = stats[ip];
                if (!stat.enrichment) {
                    stat.enrichment = std::make_shared<EnrichmentData>();
                    stat.enrichment->ip_address = ip;
                }
                for (const auto& [key, value] : abuse_data) {
                    stat.enrichment->data[key] = value;
                }
            }

            completed++;

            // Display progress bar with elapsed time
            float progress = static_cast<float>(completed) / total;
            int pos = static_cast<int>(bar_width * progress);

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

            std::cerr << "\rEnriching [";
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cerr << "=";
                else if (i == pos) std::cerr << ">";
                else std::cerr << " ";
            }
            std::cerr << "] " << completed << "/" << total << " ("
                      << static_cast<int>(progress * 100) << "%) " << elapsed << "s";
            std::cerr.flush();

            // Rate limiting - AbuseIPDB free tier allows 1000/day
            // Sleep 100ms between requests to be respectful
            if (completed < total) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        } catch (const std::exception& e) {
            std::cerr << "\nWarning: AbuseIPDB lookup failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }
    std::cerr << "\n";
}

// WHOIS lookup implementation
std::map<std::string, std::string> whois_lookup(const std::string& ip_address) {
    std::map<std::string, std::string> result;

    // Try multiple WHOIS servers in order
    std::vector<std::string> whois_servers = {
        "whois.iana.org",      // IANA will redirect to appropriate RIR
        "whois.arin.net",      // American Registry
        "whois.ripe.net",      // European Registry
        "whois.apnic.net",     // Asia Pacific Registry
        "whois.lacnic.net",    // Latin America Registry
        "whois.afrinic.net"    // African Registry
    };

    std::string whois_response;
    bool got_response = false;

    for (const auto& server : whois_servers) {
        try {
            // Create socket
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                continue;
            }

            // Set timeout
            struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            // Resolve hostname
            struct hostent* host = gethostbyname(server.c_str());
            if (!host) {
                close(sock);
                continue;
            }

            // Connect
            struct sockaddr_in server_addr;
            std::memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(43); // WHOIS port
            std::memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);

            if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                close(sock);
                continue;
            }

            // Send query
            std::string query = ip_address + "\r\n";
            if (send(sock, query.c_str(), query.length(), 0) < 0) {
                close(sock);
                continue;
            }

            // Read response
            char buffer[4096];
            std::string response;
            ssize_t bytes_read;

            while ((bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
                buffer[bytes_read] = '\0';
                response += buffer;
            }

            close(sock);

            // Check if response contains a referral
            std::string referral_server;
            if (response.find("refer:") != std::string::npos || response.find("ReferralServer:") != std::string::npos) {
                std::istringstream ref_stream(response);
                std::string ref_line;
                while (std::getline(ref_stream, ref_line)) {
                    if (ref_line.find("refer:") != std::string::npos || ref_line.find("ReferralServer:") != std::string::npos) {
                        size_t colon_pos = ref_line.find(':');
                        if (colon_pos != std::string::npos) {
                            referral_server = ref_line.substr(colon_pos + 1);
                            // Trim whitespace
                            referral_server.erase(0, referral_server.find_first_not_of(" \t\r\n"));
                            referral_server.erase(referral_server.find_last_not_of(" \t\r\n") + 1);
                            // Remove whois:// prefix if present
                            if (referral_server.find("whois://") == 0) {
                                referral_server = referral_server.substr(8);
                            }
                            // Remove any trailing path (e.g., /43)
                            size_t slash_pos = referral_server.find('/');
                            if (slash_pos != std::string::npos) {
                                referral_server = referral_server.substr(0, slash_pos);
                            }
                            break;
                        }
                    }
                }
            }

            // If we got a referral, query that server
            if (!referral_server.empty()) {
                try {
                    int ref_sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (ref_sock >= 0) {
                        struct timeval timeout;
                        timeout.tv_sec = 5;
                        timeout.tv_usec = 0;
                        setsockopt(ref_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                        setsockopt(ref_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

                        struct hostent* ref_host = gethostbyname(referral_server.c_str());
                        if (ref_host) {
                            struct sockaddr_in ref_addr;
                            std::memset(&ref_addr, 0, sizeof(ref_addr));
                            ref_addr.sin_family = AF_INET;
                            ref_addr.sin_port = htons(43);
                            std::memcpy(&ref_addr.sin_addr.s_addr, ref_host->h_addr, ref_host->h_length);

                            if (connect(ref_sock, (struct sockaddr*)&ref_addr, sizeof(ref_addr)) >= 0) {
                                std::string query = ip_address + "\r\n";
                                if (send(ref_sock, query.c_str(), query.length(), 0) >= 0) {
                                    char buffer[4096];
                                    std::string ref_response;
                                    ssize_t bytes_read;
                                    while ((bytes_read = recv(ref_sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
                                        buffer[bytes_read] = '\0';
                                        ref_response += buffer;
                                    }
                                    if (ref_response.length() > 100) {
                                        response = ref_response;
                                    }
                                }
                            }
                        }
                        close(ref_sock);
                    }
                } catch (...) {
                    // Referral failed, use original response
                }
            }

            // Check if we got a meaningful response
            if (response.length() > 100) {
                whois_response = response;
                got_response = true;
                break;
            }

        } catch (const std::exception& e) {
            // Try next server
            continue;
        }
    }

    if (!got_response || whois_response.empty()) {
        return result;
    }

    // Parse WHOIS response
    std::istringstream stream(whois_response);
    std::string line;

    std::string netname;
    std::string abuse_email;
    std::string cidr;
    std::string admin;

    while (std::getline(stream, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // Convert to lowercase for case-insensitive matching
        std::string lower_line = line;
        std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

        // Extract NetName
        if (netname.empty() && (lower_line.find("netname:") == 0 || lower_line.find("orgname:") == 0)) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                netname = line.substr(colon_pos + 1);
                netname.erase(0, netname.find_first_not_of(" \t"));
                netname.erase(netname.find_last_not_of(" \t") + 1);
            }
        }

        // Extract Abuse Email
        if (abuse_email.empty() && (lower_line.find("abuse-mailbox:") == 0 ||
            lower_line.find("orgabuseemail:") == 0 ||
            lower_line.find("abuse-c:") == 0 ||
            lower_line.find("e-mail:") == 0)) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string email = line.substr(colon_pos + 1);
                email.erase(0, email.find_first_not_of(" \t"));
                email.erase(email.find_last_not_of(" \t") + 1);
                // Check if it looks like an email
                if (email.find('@') != std::string::npos) {
                    abuse_email = email;
                }
            }
        }

        // Extract CIDR
        if (cidr.empty() && (lower_line.find("cidr:") == 0 ||
            lower_line.find("inetnum:") == 0 ||
            lower_line.find("netrange:") == 0)) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                cidr = line.substr(colon_pos + 1);
                cidr.erase(0, cidr.find_first_not_of(" \t"));
                cidr.erase(cidr.find_last_not_of(" \t") + 1);
            }
        }

        // Extract Admin contact
        if (admin.empty() && (lower_line.find("admin-c:") == 0 ||
            lower_line.find("orgadminname:") == 0 ||
            lower_line.find("orgadminhandle:") == 0 ||
            lower_line.find("person:") == 0)) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                admin = line.substr(colon_pos + 1);
                admin.erase(0, admin.find_first_not_of(" \t"));
                admin.erase(admin.find_last_not_of(" \t") + 1);
            }
        }
    }

    // Store results
    if (!netname.empty()) result["netname"] = netname;
    if (!abuse_email.empty()) result["abuse"] = abuse_email;
    if (!cidr.empty()) result["cidr"] = cidr;
    if (!admin.empty()) result["admin"] = admin;

    return result;
}

void enrich_whois_stats(std::map<std::string, IPStats>& stats, const Config& config) {
    (void)config;  // Unused for now, may be used for caching in future

    if (stats.empty()) {
        return;
    }

    // Collect IPs that need enrichment
    std::vector<std::string> ips_to_enrich;
    for (const auto& [ip, stat] : stats) {
        ips_to_enrich.push_back(ip);
    }

    std::cerr << "Enriching with WHOIS data...\n";

    size_t total = ips_to_enrich.size();
    size_t completed = 0;
    const int bar_width = 50;

    auto start_time = std::chrono::steady_clock::now();

    for (const auto& ip : ips_to_enrich) {
        try {
            auto whois_data = whois_lookup(ip);

            if (!whois_data.empty()) {
                auto& stat = stats[ip];
                if (!stat.enrichment) {
                    stat.enrichment = std::make_shared<EnrichmentData>();
                    stat.enrichment->ip_address = ip;
                }
                for (const auto& [key, value] : whois_data) {
                    stat.enrichment->data[key] = value;
                }
            }

            completed++;

            // Display progress bar with elapsed time
            float progress = static_cast<float>(completed) / total;
            int pos = static_cast<int>(bar_width * progress);

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

            std::cerr << "\rEnriching [";
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cerr << "=";
                else if (i == pos) std::cerr << ">";
                else std::cerr << " ";
            }
            std::cerr << "] " << completed << "/" << total << " ("
                      << static_cast<int>(progress * 100) << "%) " << elapsed << "s";
            std::cerr.flush();

            // Rate limiting - be respectful to WHOIS servers
            // Sleep 1 second between requests
            if (completed < total) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } catch (const std::exception& e) {
            std::cerr << "\nWarning: WHOIS lookup failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }
    std::cerr << "\n";
}

// Ping host implementation
std::string ping_host(const std::string& ip_address, int ping_count) {
    std::string result;

    // Build ping command - use -c for count, -W for timeout
    std::string cmd = "ping -c " + std::to_string(ping_count) + " -W 1 " + ip_address + " 2>&1";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return "DEAD";
    }

    char buffer[256];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    int status = pclose(pipe);

    // Check if ping failed (host unreachable)
    if (status != 0 || output.find("100% packet loss") != std::string::npos) {
        return "DEAD";
    }

    // Parse statistics line - look for patterns like:
    // rtt min/avg/max/mdev = 10.123/20.456/30.789/5.123 ms
    size_t rtt_pos = output.find("rtt min/avg/max/mdev");
    if (rtt_pos == std::string::npos) {
        // Alternative format for some systems
        rtt_pos = output.find("round-trip min/avg/max");
    }

    if (rtt_pos != std::string::npos) {
        // Find the equals sign
        size_t eq_pos = output.find("=", rtt_pos);
        if (eq_pos != std::string::npos) {
            // Extract the values: min/avg/max/mdev
            std::string values_str = output.substr(eq_pos + 1);

            // Parse: min/avg/max/mdev = X.X/Y.Y/Z.Z/W.W ms
            std::istringstream iss(values_str);
            float min_time, avg_time, max_time, mdev_time;
            char slash;

            iss >> min_time >> slash >> avg_time >> slash >> max_time >> slash >> mdev_time;

            if (iss) {
                // Format: "avg: XXms jitter: YYms"
                std::ostringstream result_stream;
                result_stream << std::fixed << std::setprecision(1);
                result_stream << "avg: " << avg_time << "ms jitter: " << mdev_time << "ms";
                return result_stream.str();
            }
        }
    }

    return "DEAD";
}

void enrich_ping_stats(std::map<std::string, IPStats>& stats, const Config& config) {
    (void)config;  // Unused for now, but kept for consistency with other enrich functions

    // Collect all IPs that need ping enrichment
    std::vector<std::string> ips_to_ping;
    for (const auto& [ip, stat] : stats) {
        // Check if already enriched with ping data
        bool has_ping = false;
        if (stat.enrichment) {
            has_ping = stat.enrichment->data.count("ping") > 0;
        }
        if (!has_ping) {
            ips_to_ping.push_back(ip);
        }
    }

    if (ips_to_ping.empty()) {
        return;
    }

    std::cout << "Enriching with ping data...\n";

    // Process IPs with progress bar
    size_t completed = 0;
    size_t total = ips_to_ping.size();
    int bar_width = 40;
    auto start_time = std::chrono::steady_clock::now();

    for (const auto& ip : ips_to_ping) {
        try {
            std::string ping_result = ping_host(ip, 3);

            auto& stat = stats[ip];
            if (!stat.enrichment) {
                stat.enrichment = std::make_shared<EnrichmentData>();
                stat.enrichment->ip_address = ip;
            }
            stat.enrichment->data["ping"] = ping_result;

            completed++;

            // Display progress bar with elapsed time
            float progress = static_cast<float>(completed) / total;
            int pos = static_cast<int>(bar_width * progress);

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

            std::cerr << "\rPinging [";
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cerr << "=";
                else if (i == pos) std::cerr << ">";
                else std::cerr << " ";
            }
            std::cerr << "] " << completed << "/" << total << " ("
                      << static_cast<int>(progress * 100) << "%) " << elapsed << "s";
            std::cerr.flush();

        } catch (const std::exception& e) {
            std::cerr << "\nWarning: Ping failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }
    std::cerr << "\n";
}

// Helper function to format certificate dates to MM/DD/YYYY HH:MM
static std::string format_cert_date(const std::string& cert_date) {
    // Input format: "Jan 13 06:24:14 2026 GMT"
    // Output format: "01/13/2026 06:24"

    if (cert_date.empty()) return "";

    static const std::map<std::string, std::string> months = {
        {"Jan", "01"}, {"Feb", "02"}, {"Mar", "03"}, {"Apr", "04"},
        {"May", "05"}, {"Jun", "06"}, {"Jul", "07"}, {"Aug", "08"},
        {"Sep", "09"}, {"Oct", "10"}, {"Nov", "11"}, {"Dec", "12"}
    };

    std::istringstream iss(cert_date);
    std::string month_str, day_str, time_str, year_str;

    iss >> month_str >> day_str >> time_str >> year_str;

    // Find month number
    auto it = months.find(month_str);
    if (it == months.end()) return cert_date;  // Return original if parse fails

    std::string month_num = it->second;

    // Extract HH:MM from time (ignore seconds)
    std::string hh_mm;
    if (time_str.length() >= 5) {
        hh_mm = time_str.substr(0, 5);  // Get HH:MM
    }

    // Format: MM/DD/YYYY HH:MM
    std::string formatted = month_num + "/" + day_str + "/" + year_str;
    if (!hh_mm.empty()) {
        formatted += " " + hh_mm;
    }

    return formatted;
}

std::map<std::string, std::string> tls_lookup(const std::string& ip_address) {
    std::map<std::string, std::string> result;

    // Get TLS version - try multiple methods for reliability
    std::string tls_version;

    // Method 1: Look for Protocol line in SSL-Session section
    std::string version_cmd = "timeout 5 openssl s_client -connect " + ip_address +
                             ":443 -servername " + ip_address +
                             " </dev/null 2>&1 | sed -n '/SSL-Session:/,/^---/p' | grep 'Protocol' | head -1";
    FILE* version_pipe = popen(version_cmd.c_str(), "r");
    if (version_pipe) {
        char version_buffer[256];
        if (fgets(version_buffer, sizeof(version_buffer), version_pipe) != nullptr) {
            std::string proto_line(version_buffer);
            if (proto_line.find(":") != std::string::npos) {
                size_t colon_pos = proto_line.find(":");
                tls_version = proto_line.substr(colon_pos + 1);
                tls_version.erase(0, tls_version.find_first_not_of(" \t\r\n"));
                tls_version.erase(tls_version.find_last_not_of(" \t\r\n") + 1);
            }
        }
        pclose(version_pipe);
    }

    // Method 2: If still empty, try looking for "New, TLSvX.X" format
    if (tls_version.empty()) {
        std::string alt_cmd = "timeout 5 openssl s_client -connect " + ip_address +
                             ":443 -servername " + ip_address +
                             " </dev/null 2>&1 | grep -o 'TLSv[0-9]\\.[0-9]' | head -1";
        FILE* alt_pipe = popen(alt_cmd.c_str(), "r");
        if (alt_pipe) {
            char alt_buffer[64];
            if (fgets(alt_buffer, sizeof(alt_buffer), alt_pipe) != nullptr) {
                tls_version = alt_buffer;
                tls_version.erase(0, tls_version.find_first_not_of(" \t\r\n"));
                tls_version.erase(tls_version.find_last_not_of(" \t\r\n") + 1);
            }
            pclose(alt_pipe);
        }
    }

    // Now get certificate information
    std::string cmd = "timeout 5 openssl s_client -connect " + ip_address + ":443 -servername " +
                      ip_address + " </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return result;  // Empty on error
    }

    char buffer[512];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    int status = pclose(pipe);
    if (status != 0 || output.empty()) {
        return result;  // Empty on error
    }

    // Parse certificate information
    std::istringstream iss(output);
    std::string line;
    bool in_validity = false;
    std::string common_name;
    std::string issuer;
    std::string algorithm;
    std::string not_before;
    std::string not_after;
    std::string key_size;

    while (std::getline(iss, line)) {
        // Extract Signature Algorithm
        if (line.find("Signature Algorithm:") != std::string::npos) {
            size_t colon_pos = line.find(":");
            if (colon_pos != std::string::npos) {
                algorithm = line.substr(colon_pos + 1);
                algorithm.erase(0, algorithm.find_first_not_of(" \t\r\n"));
                algorithm.erase(algorithm.find_last_not_of(" \t\r\n") + 1);
            }
        }

        // Extract Issuer
        if (line.find("Issuer:") != std::string::npos) {
            size_t cn_pos = line.find("CN = ");
            if (cn_pos == std::string::npos) {
                cn_pos = line.find("CN=");
                if (cn_pos != std::string::npos) {
                    issuer = line.substr(cn_pos + 3);
                }
            } else {
                issuer = line.substr(cn_pos + 5);
            }
            // Trim and clean
            size_t comma_pos = issuer.find(',');
            if (comma_pos != std::string::npos) {
                issuer = issuer.substr(0, comma_pos);
            }
            // Trim whitespace
            issuer.erase(0, issuer.find_first_not_of(" \t\r\n"));
            issuer.erase(issuer.find_last_not_of(" \t\r\n") + 1);
        }

        // Extract Subject (CN)
        if (line.find("Subject:") != std::string::npos) {
            size_t cn_pos = line.find("CN = ");
            if (cn_pos == std::string::npos) {
                cn_pos = line.find("CN=");
                if (cn_pos != std::string::npos) {
                    common_name = line.substr(cn_pos + 3);
                }
            } else {
                common_name = line.substr(cn_pos + 5);
            }
            // Trim and clean
            size_t comma_pos = common_name.find(',');
            if (comma_pos != std::string::npos) {
                common_name = common_name.substr(0, comma_pos);
            }
            // Trim whitespace
            common_name.erase(0, common_name.find_first_not_of(" \t\r\n"));
            common_name.erase(common_name.find_last_not_of(" \t\r\n") + 1);
        }

        // Extract Validity
        if (line.find("Validity") != std::string::npos) {
            in_validity = true;
        }
        if (in_validity && line.find("Not Before:") != std::string::npos) {
            size_t colon_pos = line.find(":");
            if (colon_pos != std::string::npos) {
                not_before = line.substr(colon_pos + 1);
                not_before.erase(0, not_before.find_first_not_of(" \t\r\n"));
                not_before.erase(not_before.find_last_not_of(" \t\r\n") + 1);
            }
        }
        if (in_validity && line.find("Not After :") != std::string::npos) {
            size_t colon_pos = line.find(":");
            if (colon_pos != std::string::npos) {
                not_after = line.substr(colon_pos + 1);
                not_after.erase(0, not_after.find_first_not_of(" \t\r\n"));
                not_after.erase(not_after.find_last_not_of(" \t\r\n") + 1);
            }
        }

        // Extract Public Key size
        if (line.find("Public-Key:") != std::string::npos) {
            size_t paren_pos = line.find("(");
            size_t bit_pos = line.find("bit");
            if (paren_pos != std::string::npos && bit_pos != std::string::npos) {
                key_size = line.substr(paren_pos + 1, bit_pos - paren_pos - 2);
                key_size.erase(0, key_size.find_first_not_of(" \t\r\n"));
                key_size.erase(key_size.find_last_not_of(" \t\r\n") + 1);
            }
        }
    }

    // Store results
    if (!common_name.empty()) {
        result["tls_cn"] = common_name;
    }
    if (!issuer.empty()) {
        result["tls_issuer"] = issuer;
    }
    if (!algorithm.empty()) {
        result["tls_algorithm"] = algorithm;
    }
    if (!not_before.empty()) {
        result["tls_created"] = format_cert_date(not_before);
    }
    if (!not_after.empty()) {
        result["tls_expires"] = format_cert_date(not_after);
    }
    if (!tls_version.empty()) {
        result["tls_version"] = tls_version;
    }
    if (!key_size.empty()) {
        result["tls_keysize"] = key_size;
    }

    return result;
}

void enrich_tls_stats(std::map<std::string, IPStats>& stats, const Config& config) {
    (void)config;  // Unused for now, but kept for consistency

    // Collect all IPs that need TLS enrichment
    std::vector<std::string> ips_to_check;
    for (const auto& [ip, stat] : stats) {
        // Check if already enriched with TLS data
        bool has_tls = false;
        if (stat.enrichment) {
            has_tls = stat.enrichment->data.count("tls_cn") > 0;
        }
        if (!has_tls) {
            ips_to_check.push_back(ip);
        }
    }

    if (ips_to_check.empty()) {
        return;
    }

    std::cout << "Enriching with TLS certificate data...\n";

    // Process each IP
    size_t total = ips_to_check.size();
    size_t completed = 0;
    auto start_time = std::chrono::steady_clock::now();

    for (const auto& ip : ips_to_check) {
        try {
            // Lookup TLS certificate data
            auto tls_data = tls_lookup(ip);

            // Add to enrichment data
            if (!tls_data.empty()) {
                if (!stats[ip].enrichment) {
                    stats[ip].enrichment = std::make_shared<EnrichmentData>();
                    stats[ip].enrichment->ip_address = ip;
                }

                for (const auto& [key, value] : tls_data) {
                    stats[ip].enrichment->data[key] = value;
                }
            }

            // Update progress
            completed++;
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            float progress = static_cast<float>(completed) / total;

            // Progress bar
            std::cerr << "\r[";
            int bar_width = 30;
            int pos = static_cast<int>(bar_width * progress);
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cerr << "=";
                else if (i == pos) std::cerr << ">";
                else std::cerr << " ";
            }
            std::cerr << "] " << completed << "/" << total << " ("
                      << static_cast<int>(progress * 100) << "%) " << elapsed << "s";
            std::cerr.flush();

        } catch (const std::exception& e) {
            std::cerr << "\nWarning: TLS lookup failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }
    std::cerr << "\n";
}

std::map<std::string, std::string> http_lookup(const std::string& ip_address, bool follow_redirects) {
    std::map<std::string, std::string> result;

    // Ports to check
    std::vector<int> ports = {443, 80, 3000};
    std::string working_port;
    std::string protocol;

    // Prepare redirect flag
    std::string redirect_flag = follow_redirects ? "-L " : "";

    // Find first responding port
    for (int port : ports) {
        protocol = (port == 443) ? "https" : "http";
        std::string check_cmd = "timeout 3 curl -s -I " + redirect_flag + "--max-time 3 " + protocol + "://" +
                               ip_address + ":" + std::to_string(port) + " 2>/dev/null | head -20";

        FILE* check_pipe = popen(check_cmd.c_str(), "r");
        if (check_pipe) {
            char check_buffer[256];
            std::string check_output;
            while (fgets(check_buffer, sizeof(check_buffer), check_pipe) != nullptr) {
                check_output += check_buffer;
            }
            int status = pclose(check_pipe);

            // If we got a response, use this port
            if (status == 0 && !check_output.empty() && check_output.find("HTTP") != std::string::npos) {
                working_port = std::to_string(port);
                break;
            }
        }
    }

    // If no port responded, return empty
    if (working_port.empty()) {
        return result;
    }

    // Now fetch full headers from working port
    std::string url = protocol + "://" + ip_address + ":" + working_port;
    std::string cmd = "timeout 5 curl -s -I " + redirect_flag + "--max-time 5 " + url + " 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return result;
    }

    char buffer[512];
    std::string headers;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        headers += buffer;
    }
    pclose(pipe);

    if (headers.empty()) {
        return result;
    }

    // Parse headers - capture all status codes for redirect chain
    std::istringstream iss(headers);
    std::string line;
    std::vector<std::string> status_codes;  // All status codes in chain
    std::string server;
    std::string csp;

    while (std::getline(iss, line)) {
        // Extract ALL status codes (e.g., "HTTP/1.1 200 OK")
        if (line.find("HTTP/") != std::string::npos) {
            std::istringstream status_iss(line);
            std::string http_version, code;
            status_iss >> http_version >> code;
            if (!code.empty() && code.length() == 3 && std::isdigit(code[0])) {
                status_codes.push_back(code);
            }
        }

        // Convert to lowercase for case-insensitive header matching
        std::string lower_line = line;
        std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

        // Extract Server header (keep last one - from final destination)
        if (lower_line.find("server:") == 0) {
            size_t colon_pos = line.find(":");
            if (colon_pos != std::string::npos) {
                server = line.substr(colon_pos + 1);
                server.erase(0, server.find_first_not_of(" \t\r\n"));
                server.erase(server.find_last_not_of(" \t\r\n") + 1);
            }
        }

        // Extract Content-Security-Policy header (check if any response has it)
        if (lower_line.find("content-security-policy:") == 0) {
            csp = "Yes";
        }
    }

    // Build status code chain
    std::string status_code;
    if (!status_codes.empty()) {
        if (follow_redirects && status_codes.size() > 1) {
            // Show redirect chain: "308->200"
            for (size_t i = 0; i < status_codes.size(); ++i) {
                if (i > 0) status_code += "->";
                status_code += status_codes[i];
            }
        } else {
            // Show single status code
            status_code = status_codes.back();
        }
    }

    // Get page title using curl to fetch HTML
    std::string title;
    std::string title_cmd = "timeout 5 curl -s " + redirect_flag + "--max-time 5 " + url +
                           " 2>/dev/null | grep -i '<title' | sed 's/<[^>]*>//g' | head -1";
    FILE* title_pipe = popen(title_cmd.c_str(), "r");
    if (title_pipe) {
        char title_buffer[512];
        if (fgets(title_buffer, sizeof(title_buffer), title_pipe) != nullptr) {
            title = title_buffer;
            title.erase(0, title.find_first_not_of(" \t\r\n"));
            title.erase(title.find_last_not_of(" \t\r\n") + 1);
            // Truncate if too long
            if (title.length() > 50) {
                title = title.substr(0, 47) + "...";
            }
        }
        pclose(title_pipe);
    }

    // Store results
    if (!working_port.empty()) {
        result["http_port"] = working_port;
    }
    if (!status_code.empty()) {
        result["http_status"] = status_code;
    }
    if (!server.empty()) {
        result["http_server"] = server;
    }
    if (!csp.empty()) {
        result["http_csp"] = csp;
    } else {
        result["http_csp"] = "No";
    }
    if (!title.empty()) {
        result["http_title"] = title;
    }

    return result;
}

void enrich_http_stats(std::map<std::string, IPStats>& stats, const Config& config, bool follow_redirects) {
    (void)config;  // Unused for now

    // Collect all IPs that need HTTP enrichment
    std::vector<std::string> ips_to_check;
    for (const auto& [ip, stat] : stats) {
        // Check if already enriched with HTTP data
        bool has_http = false;
        if (stat.enrichment) {
            has_http = stat.enrichment->data.count("http_port") > 0;
        }
        if (!has_http) {
            ips_to_check.push_back(ip);
        }
    }

    if (ips_to_check.empty()) {
        return;
    }

    std::cout << "Enriching with HTTP server data"
              << (follow_redirects ? " (following redirects)" : " (no redirects)") << "...\n";

    // Process each IP
    size_t total = ips_to_check.size();
    size_t completed = 0;
    auto start_time = std::chrono::steady_clock::now();

    for (const auto& ip : ips_to_check) {
        try {
            // Lookup HTTP data
            auto http_data = http_lookup(ip, follow_redirects);

            // Add to enrichment data
            if (!http_data.empty()) {
                if (!stats[ip].enrichment) {
                    stats[ip].enrichment = std::make_shared<EnrichmentData>();
                    stats[ip].enrichment->ip_address = ip;
                }

                for (const auto& [key, value] : http_data) {
                    stats[ip].enrichment->data[key] = value;
                }
            }

            // Update progress
            completed++;
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            float progress = static_cast<float>(completed) / total;

            // Progress bar
            std::cerr << "\r[";
            int bar_width = 30;
            int pos = static_cast<int>(bar_width * progress);
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cerr << "=";
                else if (i == pos) std::cerr << ">";
                else std::cerr << " ";
            }
            std::cerr << "] " << completed << "/" << total << " ("
                      << static_cast<int>(progress * 100) << "%) " << elapsed << "s";
            std::cerr.flush();

        } catch (const std::exception& e) {
            std::cerr << "\nWarning: HTTP lookup failed for " << ip << ": "
                      << e.what() << "\n";
        }
    }
    std::cerr << "\n";
}

// ============================================================================
// CIDR Matching Utilities
// ============================================================================

// Parse IPv4 CIDR and check if IP matches
static bool match_ipv4_cidr(const std::string& ip, const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    std::string network_str = cidr.substr(0, slash_pos);
    int prefix_len = 32;

    if (slash_pos != std::string::npos) {
        try {
            prefix_len = std::stoi(cidr.substr(slash_pos + 1));
        } catch (...) {
            return false;
        }
    }

    if (prefix_len < 0 || prefix_len > 32) return false;

    struct in_addr ip_addr, network_addr;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) return false;
    if (inet_pton(AF_INET, network_str.c_str(), &network_addr) != 1) return false;

    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    uint32_t ip_int = ntohl(ip_addr.s_addr);
    uint32_t network_int = ntohl(network_addr.s_addr);

    return (ip_int & mask) == (network_int & mask);
}

// Parse IPv6 CIDR and check if IP matches
static bool match_ipv6_cidr(const std::string& ip, const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    std::string network_str = cidr.substr(0, slash_pos);
    int prefix_len = 128;

    if (slash_pos != std::string::npos) {
        try {
            prefix_len = std::stoi(cidr.substr(slash_pos + 1));
        } catch (...) {
            return false;
        }
    }

    if (prefix_len < 0 || prefix_len > 128) return false;

    struct in6_addr ip_addr, network_addr;
    if (inet_pton(AF_INET6, ip.c_str(), &ip_addr) != 1) return false;
    if (inet_pton(AF_INET6, network_str.c_str(), &network_addr) != 1) return false;

    // Compare byte by byte with mask
    for (int i = 0; i < 16; i++) {
        int bits = std::min(8, prefix_len - i * 8);
        if (bits <= 0) break;

        uint8_t mask = bits == 8 ? 0xFF : (0xFF << (8 - bits));
        if ((ip_addr.s6_addr[i] & mask) != (network_addr.s6_addr[i] & mask)) {
            return false;
        }
    }

    return true;
}

// Check if IP matches CIDR (auto-detect IPv4 or IPv6)
static bool match_cidr(const std::string& ip, const std::string& cidr) {
    // Check if it's a direct IP match (no CIDR notation)
    if (cidr.find('/') == std::string::npos) {
        return ip == cidr;
    }

    // Try IPv4 first
    if (ip.find(':') == std::string::npos && cidr.find(':') == std::string::npos) {
        return match_ipv4_cidr(ip, cidr);
    }

    // Try IPv6
    if (ip.find(':') != std::string::npos && cidr.find(':') != std::string::npos) {
        return match_ipv6_cidr(ip, cidr);
    }

    return false;
}

// ============================================================================
// THUGSred Threat Intelligence
// ============================================================================

// THUGSred TI list URLs
static const std::vector<std::string> THUGSRED_TI_URLS = {
    "https://blacklist.thugs.red/services/cinsscore-army-list-badrep.csv",
    "https://blacklist.thugs.red/services/spamhaus-peer-drop-list.csv",
    "https://blacklist.thugs.red/services/nordvpn/all-addresses.ipv4.csv",
    "https://blacklist.thugs.red/services/nordvpn/all-addresses.ipv6.csv",
    "https://blacklist.thugs.red/services/mullvad/all-addresses.ipv4.csv",
    "https://blacklist.thugs.red/services/mullvad/all-addresses.ipv6.csv",
    "https://blacklist.thugs.red/ioc-addresses/phishtank-last-7-days.csv"
};

// Check if cache file is older than specified hours
static bool is_cache_stale(const std::string& filepath, size_t cache_hours) {
    struct stat st;
    if (stat(filepath.c_str(), &st) != 0) {
        return true;  // File doesn't exist
    }

    time_t now = time(nullptr);
    double seconds = difftime(now, st.st_mtime);
    return seconds > (cache_hours * 3600);  // Convert hours to seconds
}

// Download file with curl
static bool download_file(const std::string& url, const std::string& output_path) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    FILE* fp = fopen(output_path.c_str(), "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);

    fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::remove(output_path.c_str());
        return false;
    }

    return true;
}

// Get unique cache filename from URL for TI lists
static std::string get_ti_cache_filename(const std::string& url) {
    // Hash the URL using SHA256 to create unique filename
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(url.c_str()),
           url.length(), hash);

    // Convert to hex string (first 16 bytes for shorter filename)
    std::stringstream ss;
    ss << "thugsred_ti_";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    ss << ".csv";

    return ss.str();
}

// Ensure cache directory exists
static void ensure_cache_dir(const std::string& cache_dir) {
    struct stat st;
    if (stat(cache_dir.c_str(), &st) != 0) {
        mkdir(cache_dir.c_str(), 0700);
    }
}

// Parse CSV line and return IP/CIDR and message
static std::pair<std::string, std::string> parse_ti_csv_line(const std::string& line) {
    // Skip empty lines and comments
    if (line.empty() || line[0] == '#') {
        return {"", ""};
    }

    // Find first comma
    size_t comma_pos = line.find(',');
    if (comma_pos == std::string::npos) {
        return {"", ""};
    }

    std::string ip_or_cidr = line.substr(0, comma_pos);
    std::string message = line.substr(comma_pos + 1);

    // Trim whitespace
    ip_or_cidr.erase(0, ip_or_cidr.find_first_not_of(" \t\r\n"));
    ip_or_cidr.erase(ip_or_cidr.find_last_not_of(" \t\r\n") + 1);
    message.erase(0, message.find_first_not_of(" \t\r\n"));
    message.erase(message.find_last_not_of(" \t\r\n") + 1);

    // Remove quotes from message if present
    if (message.length() >= 2 && message.front() == '"' && message.back() == '"') {
        message = message.substr(1, message.length() - 2);
    }

    return {ip_or_cidr, message};
}

// Get shortened field name from filename
static std::string get_field_name_from_url(const std::string& url) {
    // Extract filename from URL
    size_t last_slash = url.find_last_of('/');
    std::string filename;
    if (last_slash != std::string::npos) {
        filename = url.substr(last_slash + 1);
    } else {
        filename = url;
    }

    // Remove .csv extension
    size_t dot_pos = filename.find(".csv");
    if (dot_pos != std::string::npos) {
        filename = filename.substr(0, dot_pos);
    }

    // Create shortened names based on filename patterns
    if (filename.find("cinsscore") != std::string::npos || filename.find("badrep") != std::string::npos) {
        return "CINSBadRep";
    } else if (filename.find("spamhaus") != std::string::npos || filename.find("peer-drop") != std::string::npos) {
        return "PeerDrop";
    } else if (filename.find("phishtank") != std::string::npos) {
        return "PhishTank";
    } else if (filename.find("nordvpn") != std::string::npos || url.find("nordvpn") != std::string::npos) {
        if (filename.find("ipv4") != std::string::npos) {
            return "NordVPN_v4";
        } else if (filename.find("ipv6") != std::string::npos) {
            return "NordVPN_v6";
        }
    } else if (filename.find("mullvad") != std::string::npos || url.find("mullvad") != std::string::npos) {
        if (filename.find("ipv4") != std::string::npos) {
            return "Mullvad_v4";
        } else if (filename.find("ipv6") != std::string::npos) {
            return "Mullvad_v6";
        }
    }

    // Fallback: use filename with underscores
    std::replace(filename.begin(), filename.end(), '-', '_');
    return filename;
}

// Load and search THUGSred TI lists
static std::map<std::string, std::string> check_thugsred_ti(const std::string& ip, const std::string& cache_dir, size_t cache_hours) {
    std::map<std::string, std::string> results;

    // Initialize all fields with "No"
    for (const auto& url : THUGSRED_TI_URLS) {
        std::string field_name = get_field_name_from_url(url);
        results[field_name] = "No";
    }

    for (const auto& url : THUGSRED_TI_URLS) {
        std::string filename = get_ti_cache_filename(url);
        std::string filepath = cache_dir + "/" + filename;
        std::string field_name = get_field_name_from_url(url);

        // Download if cache is stale
        if (is_cache_stale(filepath, cache_hours)) {
            if (!download_file(url, filepath)) {
                continue;  // Skip this list if download fails (field remains "No")
            }
        }

        // Read and search file
        std::ifstream file(filepath);
        if (!file.is_open()) continue;  // Field remains "No"

        std::string line;
        while (std::getline(file, line)) {
            auto [ip_or_cidr, message] = parse_ti_csv_line(line);

            if (ip_or_cidr.empty()) continue;

            if (match_cidr(ip, ip_or_cidr)) {
                results[field_name] = "Yes";
                break;  // Found in this list, move to next list
            }
        }

        file.close();
    }

    return results;
}

// Main THUGSred TI enrichment function for stats
void enrich_thugsred_ti_stats(std::map<std::string, IPStats>& stats, const std::string& cache_dir, size_t cache_hours) {
    if (stats.empty()) return;

    ensure_cache_dir(cache_dir);

    // Track progress
    std::atomic<size_t> completed(0);
    size_t total = stats.size();

    std::cerr << "\nEnriching IPs with THUGSred Threat Intelligence...\n";
    std::cerr << "Cache directory: " << cache_dir << "\n";
    std::cerr << "Cache TTL: " << cache_hours << " hours\n";

    for (auto& [ip, stat] : stats) {
        // Initialize enrichment if not exists
        if (!stat.enrichment) {
            stat.enrichment = std::make_shared<EnrichmentData>();
            stat.enrichment->ip_address = ip;
        }

        auto ti_results = check_thugsred_ti(ip, cache_dir, cache_hours);
        for (const auto& [field_name, value] : ti_results) {
            stat.enrichment->data[field_name] = value;
        }

        completed++;
        if (completed % 10 == 0 || completed == total) {
            std::cerr << "\rProcessed: " << completed << "/" << total;
        }
    }

    std::cerr << "\n";
}

} // namespace ipdigger
