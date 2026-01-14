#include "progress.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>

namespace ipdigger {

ProgressTracker::ProgressTracker()
    : bytes_processed(0), total_bytes(0), enabled(false), last_display_bytes(0) {
}

void ProgressTracker::init(size_t total, bool enable, const std::string& ctx) {
    total_bytes.store(total);
    bytes_processed.store(0);
    enabled = enable && (total > 10240);  // Only show for files > 10KB
    context = ctx;
    start_time = std::chrono::steady_clock::now();
    last_display_time = start_time;
    last_display_bytes = 0;
}

void ProgressTracker::add_bytes(size_t bytes_delta) {
    if (enabled) {
        bytes_processed.fetch_add(bytes_delta);
    }
}

void ProgressTracker::display() {
    if (!enabled) return;

    size_t processed = bytes_processed.load();
    size_t total = total_bytes.load();

    if (total == 0) return;

    // Quick check without lock first (optimization)
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_display_time).count();

    // Early exit if not enough time has passed (avoid mutex contention)
    if (elapsed_ms < 500 && processed < total) {
        return;
    }

    // Lock for actual display
    std::lock_guard<std::mutex> lock(display_mutex);

    // Double-check after acquiring lock (another thread might have updated)
    now = std::chrono::steady_clock::now();
    elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_display_time).count();

    // Update if either:
    // 1. At least 1% more processed since last display, OR
    // 2. At least 500ms elapsed since last display
    bool should_update = (processed - last_display_bytes >= total / 100) || (elapsed_ms >= 500);

    if (!should_update && processed < total) {
        return;
    }

    last_display_bytes = processed;
    last_display_time = now;

    // Shorten filename if too long (show last 30 chars)
    std::string display_context = context;
    if (display_context.length() > 30) {
        display_context = "..." + display_context.substr(display_context.length() - 27);
    }

    int bar_width = 25;  // Shorter bar to fit in terminal
    float progress_pct = static_cast<float>(processed) / total;
    if (progress_pct > 1.0f) progress_pct = 1.0f;
    int pos = static_cast<int>(bar_width * progress_pct);

    // Build progress bar with fixed-width formatting
    std::cerr << "\r";

    // Progress bar
    std::cerr << "[";
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cerr << "=";
        else if (i == pos) std::cerr << ">";
        else std::cerr << " ";
    }
    std::cerr << "] ";

    // Percentage (fixed 3 chars: "  0%" to "100%")
    std::cerr << std::setw(3) << get_percentage() << "% ";

    // Bytes with fixed width formatting
    double processed_mb = static_cast<double>(processed) / (1024.0 * 1024.0);
    double total_gb = static_cast<double>(total) / (1024.0 * 1024.0 * 1024.0);
    std::cerr << std::fixed << std::setprecision(0);
    std::cerr << std::setw(5) << static_cast<int>(processed_mb) << "MB/";
    std::cerr << std::setw(4) << std::setprecision(1) << total_gb << "GB ";

    // Transfer rate (fixed width: "000MB/s")
    double rate = get_rate();
    double rate_mb = rate / (1024.0 * 1024.0);
    std::cerr << std::setw(3) << static_cast<int>(rate_mb) << "MB/s ";

    // ETA with fixed width (always show, even if 0)
    size_t eta = get_eta_seconds();
    size_t eta_min = eta / 60;
    size_t eta_sec = eta % 60;
    std::cerr << std::setw(3) << eta_min << "m" << std::setfill('0') << std::setw(2) << eta_sec << std::setfill(' ') << "s ";

    // Context (filename) at the end
    if (!display_context.empty()) {
        std::cerr << display_context;
    }

    std::cerr.flush();
}

void ProgressTracker::finish() {
    if (!enabled) return;

    // Set to 100%
    bytes_processed.store(total_bytes.load());
    last_display_bytes = 0;  // Force display

    display();

    std::lock_guard<std::mutex> lock(display_mutex);
    std::cerr << "\n";
}

int ProgressTracker::get_percentage() const {
    size_t processed = bytes_processed.load();
    size_t total = total_bytes.load();

    if (total == 0) return 0;

    float pct = (static_cast<float>(processed) / total) * 100.0f;
    if (pct > 100.0f) pct = 100.0f;

    return static_cast<int>(pct);
}

size_t ProgressTracker::get_eta_seconds() const {
    size_t processed = bytes_processed.load();

    if (processed == 0) return 0;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

    if (elapsed <= 0) return 0;

    size_t total = total_bytes.load();
    size_t remaining = (processed < total) ? (total - processed) : 0;

    double rate = static_cast<double>(processed) / elapsed;
    if (rate <= 0) return 0;

    return static_cast<size_t>(remaining / rate);
}

double ProgressTracker::get_rate() const {
    size_t processed = bytes_processed.load();

    if (processed == 0) return 0.0;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();

    if (elapsed <= 0) return 0.0;

    // Convert to bytes per second
    return (static_cast<double>(processed) / elapsed) * 1000.0;
}

std::string ProgressTracker::format_bytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit_index];
    return oss.str();
}

std::string ProgressTracker::format_time(size_t seconds) {
    if (seconds == 0) return "< 1s";
    if (seconds < 60) return std::to_string(seconds) + "s";

    size_t minutes = seconds / 60;
    size_t secs = seconds % 60;

    if (minutes < 60) {
        return std::to_string(minutes) + "m " + std::to_string(secs) + "s";
    }

    size_t hours = minutes / 60;
    minutes = minutes % 60;

    return std::to_string(hours) + "h " + std::to_string(minutes) + "m";
}

} // namespace ipdigger
