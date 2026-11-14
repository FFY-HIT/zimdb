#include <rocksdb/cache.h>
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <vector>

namespace fs = std::filesystem;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

class StreamHash {
public:
    StreamHash() { SHA256_Init(&context_); }
    void add(const void* data, size_t length) {
        const auto* source = static_cast<const unsigned char*>(data);
        while (length) {
            size_t take = std::min(length, buffer_.size() - used_);
            std::memcpy(buffer_.data() + used_, source, take);
            used_ += take;
            source += take;
            length -= take;
            if (used_ == buffer_.size()) flush();
        }
    }
    std::string finish() {
        flush();
        std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
        SHA256_Final(digest.data(), &context_);
        static const char* digits = "0123456789abcdef";
        std::string result(2 * digest.size(), '0');
        for (size_t i = 0; i < digest.size(); ++i) {
            result[2 * i] = digits[digest[i] >> 4];
            result[2 * i + 1] = digits[digest[i] & 15];
        }
        return result;
    }
private:
    void flush() {
        if (used_) SHA256_Update(&context_, buffer_.data(), used_);
        used_ = 0;
    }
    SHA256_CTX context_{};
    std::array<unsigned char, 1 << 20> buffer_{};
    size_t used_ = 0;
};

struct Inventory {
    std::string json;
    uint64_t files = 0;
    uint64_t bytes = 0;
    uint64_t allocated_bytes = 0;
};

Inventory inventory(const fs::path& path) {
    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(path)) {
        require(!entry.is_directory(), "identity scanner expects flat native database directory");
        std::string name = entry.path().filename().string();
        if (name == "LOG" || name == "LOCK" || name.rfind("LOG.old.", 0) == 0) continue;
        require(name.find_first_of("\"\\\n\r\t") == std::string::npos, "unsupported metadata basename");
        files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    Inventory result;
    result.json = "[";
    for (const auto& file : files) {
        struct stat info{};
        require(::stat(file.c_str(), &info) == 0, "cannot stat native file");
        if (result.files) result.json += ',';
        result.json += "{\"name\":\"" + file.filename().string() + "\",\"bytes\":" + std::to_string(info.st_size)
            + ",\"allocated_bytes\":" + std::to_string(info.st_blocks * 512)
            + ",\"device\":" + std::to_string(info.st_dev) + ",\"inode\":" + std::to_string(info.st_ino)
            + ",\"links\":" + std::to_string(info.st_nlink)
            + ",\"mtime_sec\":" + std::to_string(info.st_mtim.tv_sec)
            + ",\"mtime_nsec\":" + std::to_string(info.st_mtim.tv_nsec)
            + ",\"ctime_sec\":" + std::to_string(info.st_ctim.tv_sec)
            + ",\"ctime_nsec\":" + std::to_string(info.st_ctim.tv_nsec) + '}';
        ++result.files;
        result.bytes += info.st_size;
        result.allocated_bytes += info.st_blocks * 512;
    }
    result.json += ']';
    return result;
}

struct Frame {
    const unsigned char* data;
    uint32_t length;
};

bool frame_less(const Frame& left, const Frame& right) {
    size_t common = std::min(left.length, right.length);
    int comparison = common ? std::memcmp(left.data, right.data, common) : 0;
    return comparison < 0 || (comparison == 0 && left.length < right.length);
}

void read_frames(const rocksdb::Slice& value, std::vector<Frame>& frames) {
    frames.clear();
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    size_t position = 0;
    while (position < value.size()) {
        require(value.size() - position >= 4, "truncated native packed-value header");
        uint32_t length = uint32_t(bytes[position]) | uint32_t(bytes[position + 1]) << 8
            | uint32_t(bytes[position + 2]) << 16 | uint32_t(bytes[position + 3]) << 24;
        position += 4;
        require(length <= value.size() - position, "truncated native packed-value body");
        frames.push_back({bytes + position, length});
        position += length;
    }
}

int main(int argc, char** argv) {
    try {
        require(argc == 4, "usage: com_kv_identity DATABASE OUTPUT_JSON EXPECTED_KV_SHA256");
        const uint16_t endian = 1;
        require(*reinterpret_cast<const uint8_t*>(&endian) == 1, "protocol implementation requires little-endian host");
        const auto start = std::chrono::steady_clock::now();
        fs::path path = argv[1];
        auto before = inventory(path);
        rocksdb::BlockBasedTableOptions table;
        table.block_cache = rocksdb::NewLRUCache(8 << 20);
        rocksdb::Options options;
        options.create_if_missing = false;
        options.max_open_files = 64;
        options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
        rocksdb::DB* opened = nullptr;
        auto status = rocksdb::DB::OpenForReadOnly(options, path.string(), &opened, false);
        if (!status.ok()) throw std::runtime_error(status.ToString());
        std::unique_ptr<rocksdb::DB> database(opened);
        rocksdb::ReadOptions read;
        read.fill_cache = false;
        read.verify_checksums = true;
        read.readahead_size = 1 << 20;
        std::unique_ptr<rocksdb::Iterator> iterator(database->NewIterator(read));
        StreamHash hash;
        StreamHash sorted_frame_hash;
        std::vector<Frame> frames;
        frames.reserve(16);
        uint64_t keys = 0, records = 0, key_bytes = 0, value_bytes = 0;
        uint64_t reordered_keys = 0, reordered_records = 0;
        uint64_t maximum_frames = 0, maximum_packed_value_bytes = 0;
        uint64_t maximum_frame_descriptor_bytes = 0, maximum_visible_group_and_descriptors = 0;
        for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
            auto key = iterator->key();
            auto value = iterator->value();
            uint64_t lengths[2] = {key.size(), value.size()};
            hash.add(lengths, sizeof(lengths));
            hash.add(key.data(), key.size());
            hash.add(value.data(), value.size());
            sorted_frame_hash.add(lengths, sizeof(lengths));
            sorted_frame_hash.add(key.data(), key.size());
            read_frames(value, frames);
            bool already_sorted = std::is_sorted(frames.begin(), frames.end(), frame_less);
            if (already_sorted) {
                sorted_frame_hash.add(value.data(), value.size());
            } else {
                ++reordered_keys;
                reordered_records += frames.size();
                std::sort(frames.begin(), frames.end(), frame_less);
                for (const auto& frame : frames) {
                    sorted_frame_hash.add(&frame.length, sizeof(frame.length));
                    sorted_frame_hash.add(frame.data, frame.length);
                }
            }
            maximum_frames = std::max(maximum_frames, static_cast<uint64_t>(frames.size()));
            maximum_packed_value_bytes = std::max(maximum_packed_value_bytes, static_cast<uint64_t>(value.size()));
            uint64_t descriptor_bytes = frames.capacity() * sizeof(Frame);
            maximum_frame_descriptor_bytes = std::max(maximum_frame_descriptor_bytes, descriptor_bytes);
            maximum_visible_group_and_descriptors = std::max(maximum_visible_group_and_descriptors,
                static_cast<uint64_t>(key.size() + value.size()) + descriptor_bytes);
            ++keys;
            records += frames.size();
            key_bytes += key.size();
            value_bytes += value.size();
            if (keys % 8000000 == 0)
                std::cerr << "{\"kind\":\"PROGRESS\",\"grouped_keys\":" << keys
                          << ",\"elapsed_seconds\":"
                          << std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() << "}\n";
        }
        status = iterator->status();
        if (!status.ok()) throw std::runtime_error(status.ToString());
        iterator.reset();
        database.reset();
        auto after = inventory(path);
        require(before.json == after.json, "native file metadata changed during read-only scan");
        std::string actual = hash.finish();
        std::string sorted_actual = sorted_frame_hash.finish();
        struct rusage usage{};
        ::getrusage(RUSAGE_SELF, &usage);
        std::ofstream output(argv[2]);
        require(output.good(), "cannot open identity output");
        output << "{\n\"status\":\"PASS_READ_ONLY_LOGICAL_KV_SCAN\",\n\"database\":\"" << path.string()
               << "\",\n\"sorted_grouped_kv_sha256\":\"" << actual
               << "\",\n\"expected_qualified_kv_sha256\":\"" << argv[3]
               << "\",\n\"matches_qualified_reference\":" << (actual == argv[3] ? "true" : "false")
               << ",\n\"sorted_frames_grouped_kv_sha256\":\"" << sorted_actual
               << "\",\n\"matches_qualified_reference_after_frame_sort\":" << (sorted_actual == argv[3] ? "true" : "false")
               << ",\n\"keys_with_noncanonical_frame_order\":" << reordered_keys
               << ",\n\"records_in_reordered_keys\":" << reordered_records
               << ",\n\"maximum_frames_per_key\":" << maximum_frames
               << ",\n\"maximum_packed_value_bytes\":" << maximum_packed_value_bytes
               << ",\n\"maximum_frame_descriptor_capacity_bytes\":" << maximum_frame_descriptor_bytes
               << ",\n\"maximum_visible_group_and_descriptor_bytes\":" << maximum_visible_group_and_descriptors
               << ",\n\"grouped_key_count\":" << keys << ",\n\"native_map_record_count\":" << records
               << ",\n\"key_bytes\":" << key_bytes << ",\n\"packed_value_bytes\":" << value_bytes
               << ",\n\"native_bytes\":" << before.bytes << ",\n\"native_allocated_bytes\":" << before.allocated_bytes
               << ",\n\"native_file_metadata_unchanged\":true,\n\"files_before\":" << before.json
               << ",\n\"files_after\":" << after.json
               << ",\n\"self_peak_rss_kib\":" << usage.ru_maxrss << ",\n\"elapsed_seconds\":"
               << std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count()
               << ",\n\"protocol\":\"ordered native KV including control keys; LE64 key length, LE64 value length, exact key bytes, exact packed value bytes\""
               << ",\n\"frame_order_protocol\":\"historical tasknative buildRDB comparator: unsigned native Value payload byte lexicographic order within each key, preserving duplicates; reemit LE32 payload length and exact payload; key order unchanged\""
               << ",\n\"scope\":\"read-only iterator with checksum verification; frozen non-diagnostic device/inode/size/mtime/ctime metadata checked; no physical SST double hash; no RR-order-independent equality inferred from a mismatched packed-value digest\"\n}\n";
        output.close();
        require(output.good(), "cannot finish identity output");
        std::cout << "identity scan complete, grouped keys " << keys
                  << ", raw reference match " << (actual == argv[3] ? "true" : "false")
                  << ", frame-sorted reference match " << (sorted_actual == argv[3] ? "true" : "false") << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "identity error: " << error.what() << '\n';
        return 1;
    }
}
