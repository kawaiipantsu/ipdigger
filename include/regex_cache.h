#ifndef REGEX_CACHE_H
#define REGEX_CACHE_H

#include <regex>
#include <vector>
#include <utility>
#include <string>

namespace ipdigger {

/**
 * Pre-compiled regex patterns for performance optimization
 * Patterns are compiled once in the constructor and reused across all lines/files
 * This eliminates the expensive regex compilation overhead on every line
 */
struct RegexCache {
    // IPv4 pattern for extracting IP addresses
    std::regex ipv4_pattern;

    // IPv6 pattern for extracting IP addresses
    std::regex ipv6_pattern;

    // Date patterns: vector of (regex, format_string) pairs
    // Tried in order; first match wins
    std::vector<std::pair<std::regex, std::string>> date_patterns;

    /**
     * Constructor: Pre-compiles all regex patterns
     * This is called once at program startup, eliminating per-line compilation overhead
     */
    RegexCache();
};

} // namespace ipdigger

#endif // REGEX_CACHE_H
