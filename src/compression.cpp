#include "compression.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <sys/stat.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

namespace ipdigger {

// ============================================================================
// Compression Detection
// ============================================================================

CompressionType detect_compression(const std::string& filename) {
    // Check file extension
    if (filename.size() >= 3) {
        std::string ext = filename.substr(filename.size() - 3);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (ext == ".gz") {
            return CompressionType::GZIP;
        }
    }

    if (filename.size() >= 4) {
        std::string ext = filename.substr(filename.size() - 4);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (ext == ".bz2") {
            return CompressionType::BZIP2;
        }
    }

    if (filename.size() >= 3) {
        std::string ext = filename.substr(filename.size() - 3);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (ext == ".xz") {
            return CompressionType::XZ;
        }
    }

    return CompressionType::NONE;
}

bool is_compressed(const std::string& filename) {
    return detect_compression(filename) != CompressionType::NONE;
}

size_t get_file_size(const std::string& filename) {
    struct stat st;
    if (stat(filename.c_str(), &st) == 0) {
        return static_cast<size_t>(st.st_size);
    }
    return 0;
}

// ============================================================================
// RegularFileReader Implementation
// ============================================================================

class RegularFileReader::Impl {
public:
    std::ifstream file;
    size_t bytes_read;
    bool at_eof;

    explicit Impl(const std::string& filename)
        : file(filename), bytes_read(0), at_eof(false) {
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
    }
};

RegularFileReader::RegularFileReader(const std::string& filename)
    : pImpl(std::make_unique<Impl>(filename)) {}

RegularFileReader::~RegularFileReader() = default;

bool RegularFileReader::getline(std::string& line) {
    if (pImpl->at_eof) {
        return false;
    }

    std::streampos before = pImpl->file.tellg();
    if (std::getline(pImpl->file, line)) {
        std::streampos after = pImpl->file.tellg();
        if (after != -1 && before != -1) {
            pImpl->bytes_read += static_cast<size_t>(after - before);
        }
        return true;
    }

    pImpl->at_eof = true;
    return false;
}

bool RegularFileReader::eof() const {
    return pImpl->at_eof;
}

size_t RegularFileReader::tell() const {
    return pImpl->bytes_read;
}

// ============================================================================
// GzipReader Implementation
// ============================================================================

class GzipReader::Impl {
public:
    gzFile file;
    size_t bytes_read;
    bool at_eof;
    static constexpr size_t BUFFER_SIZE = 65536; // 64KB buffer
    char buffer[BUFFER_SIZE];

    explicit Impl(const std::string& filename)
        : file(nullptr), bytes_read(0), at_eof(false) {
        file = gzopen(filename.c_str(), "rb");
        if (file == nullptr) {
            throw std::runtime_error("Failed to open gzip file: " + filename);
        }

        // Set buffer for better performance
        gzbuffer(file, BUFFER_SIZE);
    }

    ~Impl() {
        if (file != nullptr) {
            gzclose(file);
        }
    }
};

GzipReader::GzipReader(const std::string& filename)
    : pImpl(std::make_unique<Impl>(filename)) {}

GzipReader::~GzipReader() = default;

bool GzipReader::getline(std::string& line) {
    if (pImpl->at_eof) {
        return false;
    }

    line.clear();

    // Read line using gzgets
    z_off_t before = gztell(pImpl->file);
    char* result = gzgets(pImpl->file, pImpl->buffer, Impl::BUFFER_SIZE);

    if (result == nullptr) {
        // Check for errors
        int errnum;
        const char* error_msg = gzerror(pImpl->file, &errnum);
        if (errnum != Z_OK && errnum != Z_STREAM_END) {
            throw std::runtime_error(std::string("Gzip decompression error: ") + error_msg);
        }
        pImpl->at_eof = true;
        return false;
    }

    // Remove trailing newline if present
    line = pImpl->buffer;
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    // Update bytes read (compressed bytes)
    z_off_t after = gztell(pImpl->file);
    if (after > before) {
        pImpl->bytes_read += static_cast<size_t>(after - before);
    }

    return true;
}

bool GzipReader::eof() const {
    return pImpl->at_eof;
}

size_t GzipReader::tell() const {
    return pImpl->bytes_read;
}

// ============================================================================
// Bzip2Reader Implementation
// ============================================================================

class Bzip2Reader::Impl {
public:
    BZFILE* file;
    FILE* raw_file;
    size_t bytes_read;
    bool at_eof;
    static constexpr size_t BUFFER_SIZE = 65536; // 64KB buffer
    char buffer[BUFFER_SIZE];
    std::string leftover; // For partial lines

    explicit Impl(const std::string& filename)
        : file(nullptr), raw_file(nullptr), bytes_read(0), at_eof(false) {
        raw_file = fopen(filename.c_str(), "rb");
        if (raw_file == nullptr) {
            throw std::runtime_error("Failed to open bzip2 file: " + filename);
        }

        int bzerror;
        file = BZ2_bzReadOpen(&bzerror, raw_file, 0, 0, nullptr, 0);
        if (file == nullptr || bzerror != BZ_OK) {
            if (raw_file != nullptr) {
                fclose(raw_file);
            }
            throw std::runtime_error("Failed to initialize bzip2 reader: " + std::to_string(bzerror));
        }
    }

    ~Impl() {
        if (file != nullptr) {
            int bzerror;
            BZ2_bzReadClose(&bzerror, file);
        }
        if (raw_file != nullptr) {
            fclose(raw_file);
        }
    }
};

Bzip2Reader::Bzip2Reader(const std::string& filename)
    : pImpl(std::make_unique<Impl>(filename)) {}

Bzip2Reader::~Bzip2Reader() = default;

bool Bzip2Reader::getline(std::string& line) {
    line.clear();

    // Use leftover from previous read if available
    if (!pImpl->leftover.empty()) {
        size_t newline_pos = pImpl->leftover.find('\n');
        if (newline_pos != std::string::npos) {
            line = pImpl->leftover.substr(0, newline_pos);
            pImpl->leftover = pImpl->leftover.substr(newline_pos + 1);

            // Remove trailing \r if present
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return true;
        }
        line = pImpl->leftover;
        pImpl->leftover.clear();
    }

    // If no leftover data and already at EOF, we're done
    if (pImpl->at_eof) {
        return !line.empty();
    }

    // Read more data
    while (true) {
        int bzerror;
        int bytes = BZ2_bzRead(&bzerror, pImpl->file, pImpl->buffer, Impl::BUFFER_SIZE - 1);

        // Track approximate progress (uncompressed bytes as proxy)
        if (bytes > 0) {
            pImpl->bytes_read += static_cast<size_t>(bytes);
        }

        // Check for actual errors (not BZ_OK or BZ_STREAM_END)
        if (bzerror != BZ_OK && bzerror != BZ_STREAM_END) {
            throw std::runtime_error("Bzip2 decompression error: " + std::to_string(bzerror));
        }

        // Check if we're done reading
        if (bytes <= 0) {
            pImpl->at_eof = true;
            return !line.empty();
        }

        pImpl->buffer[bytes] = '\0';
        std::string chunk(pImpl->buffer, bytes);

        // Mark EOF if stream ended (do this before processing data)
        bool stream_ended = (bzerror == BZ_STREAM_END);
        if (stream_ended) {
            pImpl->at_eof = true;
        }

        // Look for newline in chunk
        size_t newline_pos = chunk.find('\n');
        if (newline_pos != std::string::npos) {
            line += chunk.substr(0, newline_pos);
            pImpl->leftover = chunk.substr(newline_pos + 1);

            // Remove trailing \r if present
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return true;
        }

        // No newline found, append entire chunk
        line += chunk;

        // If stream ended and no newline, return what we have
        if (stream_ended) {
            return !line.empty();
        }
    }
}

bool Bzip2Reader::eof() const {
    return pImpl->at_eof;
}

size_t Bzip2Reader::tell() const {
    return pImpl->bytes_read;
}

// ============================================================================
// XzReader Implementation
// ============================================================================

class XzReader::Impl {
public:
    FILE* file;
    lzma_stream stream;
    size_t bytes_read;
    bool at_eof;
    static constexpr size_t BUFFER_SIZE = 65536; // 64KB buffers
    uint8_t in_buffer[BUFFER_SIZE];
    uint8_t out_buffer[BUFFER_SIZE];
    size_t out_pos;
    size_t out_size;
    std::string leftover;

    explicit Impl(const std::string& filename)
        : file(nullptr), stream(LZMA_STREAM_INIT), bytes_read(0),
          at_eof(false), out_pos(0), out_size(0) {

        file = fopen(filename.c_str(), "rb");
        if (file == nullptr) {
            throw std::runtime_error("Failed to open XZ file: " + filename);
        }

        // Initialize XZ decoder
        lzma_ret ret = lzma_stream_decoder(&stream, UINT64_MAX, LZMA_CONCATENATED);
        if (ret != LZMA_OK) {
            fclose(file);
            throw std::runtime_error("Failed to initialize XZ decoder: " + std::to_string(ret));
        }

        stream.next_in = nullptr;
        stream.avail_in = 0;
        stream.next_out = out_buffer;
        stream.avail_out = BUFFER_SIZE;
    }

    ~Impl() {
        lzma_end(&stream);
        if (file != nullptr) {
            fclose(file);
        }
    }

    bool read_more_data() {
        if (stream.avail_in == 0 && !feof(file)) {
            size_t bytes = fread(in_buffer, 1, BUFFER_SIZE, file);
            if (bytes > 0) {
                bytes_read += bytes;
                stream.next_in = in_buffer;
                stream.avail_in = bytes;
                return true;
            }
        }
        return stream.avail_in > 0;
    }

    bool decompress_chunk() {
        if (out_pos < out_size) {
            return true; // Still have data in output buffer
        }

        if (!read_more_data() && stream.avail_in == 0) {
            return false;
        }

        stream.next_out = out_buffer;
        stream.avail_out = BUFFER_SIZE;

        lzma_ret ret = lzma_code(&stream, stream.avail_in == 0 ? LZMA_FINISH : LZMA_RUN);

        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
            throw std::runtime_error("XZ decompression error: " + std::to_string(ret));
        }

        out_size = BUFFER_SIZE - stream.avail_out;
        out_pos = 0;

        if (ret == LZMA_STREAM_END && out_size == 0) {
            return false;
        }

        return out_size > 0;
    }
};

XzReader::XzReader(const std::string& filename)
    : pImpl(std::make_unique<Impl>(filename)) {}

XzReader::~XzReader() = default;

bool XzReader::getline(std::string& line) {
    if (pImpl->at_eof) {
        return false;
    }

    line.clear();

    // Use leftover from previous read if available
    if (!pImpl->leftover.empty()) {
        size_t newline_pos = pImpl->leftover.find('\n');
        if (newline_pos != std::string::npos) {
            line = pImpl->leftover.substr(0, newline_pos);
            pImpl->leftover = pImpl->leftover.substr(newline_pos + 1);

            // Remove trailing \r if present
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return true;
        }
        line = pImpl->leftover;
        pImpl->leftover.clear();
    }

    // Read and decompress data until we find a newline
    while (true) {
        // Decompress more data if needed
        if (pImpl->out_pos >= pImpl->out_size) {
            if (!pImpl->decompress_chunk()) {
                pImpl->at_eof = true;
                return !line.empty();
            }
        }

        // Look for newline in current output buffer
        while (pImpl->out_pos < pImpl->out_size) {
            char c = static_cast<char>(pImpl->out_buffer[pImpl->out_pos++]);

            if (c == '\n') {
                // Remove trailing \r if present
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                return true;
            }

            line += c;
        }
    }
}

bool XzReader::eof() const {
    return pImpl->at_eof;
}

size_t XzReader::tell() const {
    return pImpl->bytes_read;
}

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<LineReader> create_reader(const std::string& filename) {
    CompressionType type = detect_compression(filename);

    switch (type) {
        case CompressionType::NONE:
            return std::make_unique<RegularFileReader>(filename);

        case CompressionType::GZIP:
            return std::make_unique<GzipReader>(filename);

        case CompressionType::BZIP2:
            return std::make_unique<Bzip2Reader>(filename);

        case CompressionType::XZ:
            return std::make_unique<XzReader>(filename);

        default:
            throw std::runtime_error("Unknown compression type for file: " + filename);
    }
}

} // namespace ipdigger
