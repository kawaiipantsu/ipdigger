#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <string>
#include <memory>
#include <cstddef>

namespace ipdigger {

/**
 * Supported compression types, detected by file extension
 */
enum class CompressionType {
    NONE,    // Regular uncompressed file
    GZIP,    // .gz files (zlib)
    BZIP2,   // .bz2 files (libbz2)
    XZ       // .xz files (liblzma)
};

/**
 * Detect compression type from filename extension
 * @param filename Path to the file
 * @return CompressionType based on extension (.gz, .bz2, .xz)
 */
CompressionType detect_compression(const std::string& filename);

/**
 * Check if a file is compressed (any format)
 * @param filename Path to the file
 * @return true if file has a compressed extension
 */
bool is_compressed(const std::string& filename);

/**
 * Get file size in bytes
 * @param filename Path to the file
 * @return File size in bytes, or 0 if file doesn't exist
 */
size_t get_file_size(const std::string& filename);

/**
 * Abstract interface for reading lines from files (compressed or not)
 * Provides uniform API for different compression formats
 */
class LineReader {
public:
    virtual ~LineReader() = default;

    /**
     * Read next line from the file
     * @param line Output string to store the line (without newline)
     * @return true if line was read successfully, false on EOF
     * @throws std::runtime_error on decompression errors
     */
    virtual bool getline(std::string& line) = 0;

    /**
     * Check if end of file reached
     * @return true if at EOF
     */
    virtual bool eof() const = 0;

    /**
     * Get current position (bytes read so far)
     * For compressed files, this is compressed bytes read
     * @return Number of bytes processed
     */
    virtual size_t tell() const = 0;
};

/**
 * LineReader for regular uncompressed files
 * Wraps std::ifstream for consistency with compressed readers
 */
class RegularFileReader : public LineReader {
public:
    explicit RegularFileReader(const std::string& filename);
    ~RegularFileReader() override;

    bool getline(std::string& line) override;
    bool eof() const override;
    size_t tell() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * LineReader for gzip-compressed files (.gz)
 * Uses zlib library for decompression
 */
class GzipReader : public LineReader {
public:
    explicit GzipReader(const std::string& filename);
    ~GzipReader() override;

    bool getline(std::string& line) override;
    bool eof() const override;
    size_t tell() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * LineReader for bzip2-compressed files (.bz2)
 * Uses libbz2 library for decompression
 */
class Bzip2Reader : public LineReader {
public:
    explicit Bzip2Reader(const std::string& filename);
    ~Bzip2Reader() override;

    bool getline(std::string& line) override;
    bool eof() const override;
    size_t tell() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * LineReader for XZ-compressed files (.xz)
 * Uses liblzma library for decompression
 */
class XzReader : public LineReader {
public:
    explicit XzReader(const std::string& filename);
    ~XzReader() override;

    bool getline(std::string& line) override;
    bool eof() const override;
    size_t tell() const override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * Factory function to create appropriate LineReader for a file
 * Automatically detects compression type from extension
 * @param filename Path to the file
 * @return Unique pointer to LineReader instance
 * @throws std::runtime_error if file cannot be opened
 */
std::unique_ptr<LineReader> create_reader(const std::string& filename);

} // namespace ipdigger

#endif // COMPRESSION_H
