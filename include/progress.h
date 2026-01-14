#ifndef PROGRESS_H
#define PROGRESS_H

#include <atomic>
#include <mutex>
#include <chrono>
#include <string>

namespace ipdigger {

/**
 * Thread-safe progress tracker with ETA calculation
 * Tracks bytes processed and displays progress bar with transfer rate and time remaining
 */
class ProgressTracker {
private:
    std::atomic<size_t> bytes_processed;
    std::atomic<size_t> total_bytes;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_display_time;
    std::mutex display_mutex;
    bool enabled;
    std::string context;  // e.g., filename or "Parsing files"
    size_t last_display_bytes;

public:
    /**
     * Constructor
     */
    ProgressTracker();

    /**
     * Initialize progress tracking
     * @param total Total bytes to process
     * @param enable Whether to show progress (disabled for JSON output mode)
     * @param ctx Context string (filename or description)
     */
    void init(size_t total, bool enable, const std::string& ctx = "");

    /**
     * Update progress by adding processed bytes
     * @param bytes_delta Number of bytes processed since last update
     */
    void add_bytes(size_t bytes_delta);

    /**
     * Display current progress (thread-safe)
     * Only displays if significant progress was made (> 1% or > 100ms elapsed)
     */
    void display();

    /**
     * Force display of final progress (100%)
     */
    void finish();

    /**
     * Get current progress percentage (0-100)
     */
    int get_percentage() const;

    /**
     * Get estimated time remaining in seconds
     * Returns 0 if not enough data to estimate
     */
    size_t get_eta_seconds() const;

    /**
     * Format bytes as human-readable string (MB, GB, etc.)
     * @param bytes Number of bytes
     * @return Formatted string like "45.2 MB"
     */
    static std::string format_bytes(size_t bytes);

    /**
     * Format seconds as human-readable time string
     * @param seconds Number of seconds
     * @return Formatted string like "2m 15s" or "45s" or "< 1s"
     */
    static std::string format_time(size_t seconds);

private:
    /**
     * Get transfer rate in bytes per second
     */
    double get_rate() const;
};

} // namespace ipdigger

#endif // PROGRESS_H
