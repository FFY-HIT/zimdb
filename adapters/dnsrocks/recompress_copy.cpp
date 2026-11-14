#include <rocksdb/utilities/options_util.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/table_properties.h>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <map>
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

using Clock = std::chrono::steady_clock;

double seconds(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

std::string quote(const std::string& input) {
    std::ostringstream output;
    output << '"';
    for (unsigned char byte : input) {
        if (byte == '"' || byte == '\\') output << '\\' << char(byte);
        else if (byte < 32) {
            static const char* hex = "0123456789abcdef";
            output << "\\u00" << hex[byte >> 4] << hex[byte & 15];
        } else output << char(byte);
    }
    output << '"';
    return output.str();
}

void checked(const rocksdb::Status& status) {
    if (!status.ok()) throw std::runtime_error(status.ToString());
}

void stage(const std::string& name, Clock::time_point start) {
    std::cout << "{\"kind\":\"STAGE\",\"stage\":" << quote(name)
              << ",\"seconds\":" << seconds(start) << "}" << std::endl;
}

struct Identity {
    std::string raw, canonical;
    uint64_t keys = 0, frames = 0, key_bytes = 0, value_bytes = 0;
    std::string json() const {
        return "{\"raw_grouped_kv_sha256\":" + quote(raw)
            + ",\"frame_canonical_kv_sha256\":" + quote(canonical)
            + ",\"grouped_keys\":" + std::to_string(keys)
            + ",\"native_frames\":" + std::to_string(frames)
            + ",\"key_bytes\":" + std::to_string(key_bytes)
            + ",\"packed_value_bytes\":" + std::to_string(value_bytes) + "}";
    }
};

Identity identity(rocksdb::DB* database) {
    rocksdb::ReadOptions read;
    read.fill_cache = false;
    read.verify_checksums = true;
    read.readahead_size = 1 << 20;
    std::unique_ptr<rocksdb::Iterator> iterator(database->NewIterator(read));
    StreamHash raw, canonical;
    std::vector<Frame> frames;
    frames.reserve(32);
    Identity result;
    for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
        auto key = iterator->key(), value = iterator->value();
        uint64_t lengths[2] = {key.size(), value.size()};
        raw.add(lengths, sizeof(lengths));
        raw.add(key.data(), key.size());
        raw.add(value.data(), value.size());
        canonical.add(lengths, sizeof(lengths));
        canonical.add(key.data(), key.size());
        read_frames(value, frames);
        if (std::is_sorted(frames.begin(), frames.end(), frame_less)) {
            canonical.add(value.data(), value.size());
        } else {
            std::sort(frames.begin(), frames.end(), frame_less);
            for (const auto& frame : frames) {
                canonical.add(&frame.length, sizeof(frame.length));
                canonical.add(frame.data, frame.length);
            }
        }
        ++result.keys;
        result.frames += frames.size();
        result.key_bytes += key.size();
        result.value_bytes += value.size();
        if (result.keys % 8000000 == 0)
            std::cerr << "{\"kind\":\"PROGRESS\",\"identity_keys\":" << result.keys << "}\n";
    }
    checked(iterator->status());
    result.raw = raw.finish();
    result.canonical = canonical.finish();
    return result;
}

Identity readonly_identity(const fs::path& path) {
    rocksdb::Options options;
    options.create_if_missing = false;
    options.max_open_files = 64;
    rocksdb::BlockBasedTableOptions table;
    table.block_cache = rocksdb::NewLRUCache(8 << 20);
    options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
    rocksdb::DB* opened = nullptr;
    checked(rocksdb::DB::OpenForReadOnly(options, path.string(), &opened, false));
    std::unique_ptr<rocksdb::DB> database(opened);
    return identity(database.get());
}

void guard(const Identity& actual, const std::string& raw, const std::string& canonical) {
    require(actual.raw == raw, "raw grouped-KV identity mismatch");
    require(actual.canonical == canonical, "frame-canonical grouped-KV identity mismatch");
}

void durable_directory(const fs::path& path) {
    for (const auto& entry : fs::directory_iterator(path)) {
        require(entry.is_regular_file() && !entry.is_symlink(), "flat regular native directory required");
        int descriptor = ::open(entry.path().c_str(), O_RDONLY | O_CLOEXEC);
        require(descriptor >= 0, "cannot open output file for sync");
        int result = ::fsync(descriptor);
        int close_result = ::close(descriptor);
        require(result == 0 && close_result == 0, "output file sync failed");
    }
    for (const auto& directory : {path, path.parent_path()}) {
        int descriptor = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        require(descriptor >= 0, "cannot open output directory for sync");
        int result = ::fsync(descriptor);
        int close_result = ::close(descriptor);
        require(result == 0 && close_result == 0, "output directory sync failed");
    }
}

std::string table_properties(rocksdb::DB* database) {
    rocksdb::TablePropertiesCollection properties;
    checked(database->GetPropertiesOfAllTables(&properties));
    std::ostringstream output;
    output << '[';
    bool first = true;
    for (const auto& row : properties) {
        if (!first) output << ',';
        first = false;
        const auto& property = *row.second;
        require(property.compression_name.find("ZSTD") != std::string::npos,
                "forced rewrite left a non-ZSTD native SST");
        output << "{\"file\":" << quote(fs::path(row.first).filename().string())
               << ",\"compression_name\":" << quote(property.compression_name)
               << ",\"num_entries\":" << property.num_entries
               << ",\"num_data_blocks\":" << property.num_data_blocks
               << ",\"raw_key_size\":" << property.raw_key_size
               << ",\"raw_value_size\":" << property.raw_value_size
               << ",\"data_size\":" << property.data_size
               << ",\"index_size\":" << property.index_size
               << ",\"filter_size\":" << property.filter_size << '}';
    }
    require(!first, "forced rewrite has no SST properties");
    output << ']';
    return output.str();
}

std::map<std::string, uint64_t> process_io() {
    std::ifstream stream("/proc/self/io");
    std::map<std::string, uint64_t> result;
    std::string name;
    uint64_t value;
    while (stream >> name >> value) {
        if (!name.empty() && name.back() == ':') name.pop_back();
        result[name] = value;
    }
    require(!result.empty(), "cannot read process IO counters");
    return result;
}

std::string io_difference(const std::map<std::string,uint64_t>& before,
                          const std::map<std::string,uint64_t>& after) {
    std::string result = "{";
    bool first = true;
    for (const auto& entry : after) {
        if (!first) result += ',';
        first = false;
        result += quote(entry.first) + ':' + std::to_string(entry.second - before.at(entry.first));
    }
    return result + '}';
}

bool contains_path(const fs::path& parent, const fs::path& child) {
    auto left = parent.begin(), right = child.begin();
    for (; left != parent.end(); ++left, ++right)
        if (right == child.end() || *left != *right) return false;
    return true;
}

int main(int argc, char** argv) {
    try {
        require(argc == 8, "usage: recompress_copy SOURCE NEW_OUTPUT EXPECTED_RAW_SHA EXPECTED_FRAME_CANONICAL_SHA STATS_JSON BLOCK_BYTES_OR_ZERO SOURCE_PROVEN_FULL_BLOOM_BITS10");
        const uint16_t endian = 1;
        require(*reinterpret_cast<const uint8_t*>(&endian) == 1, "identity protocol requires little endian");
        fs::path source = fs::canonical(argv[1]);
        fs::path output = fs::weakly_canonical(argv[2]);
        fs::path campaign = fs::canonical("/home/administrator/zimdb_queryable_20261113");
        require(contains_path(campaign, output) && output != campaign, "output must remain inside campaign directory");
        require(!contains_path(source, output) && !contains_path(output, source), "source and output paths must be disjoint");
        require(!fs::exists(output), "new output directory already exists");
        require(fs::is_directory(output.parent_path()), "output parent directory must exist");
        fs::path stats_path = fs::weakly_canonical(argv[5]);
        require(!contains_path(source, stats_path) && !contains_path(output, stats_path), "stats must be outside native databases");
        require(!fs::exists(stats_path) && fs::is_directory(stats_path.parent_path()), "new stats path and existing parent required");
        std::string expected_raw = argv[3], expected_canonical = argv[4];
        require(expected_raw.size() == 64 && expected_canonical.size() == 64, "expected SHA256 digests required");
        uint64_t block_bytes = std::stoull(argv[6]);
        uint64_t source_bloom_bits = std::stoull(argv[7]);
        require(source_bloom_bits == 10, "this qualified source control requires source-proven full Bloom bits10");
        auto original = inventory(source);
        const auto total_start = Clock::now();
        auto start = Clock::now();
        fs::create_directory(output);
        for (const auto& entry : fs::directory_iterator(source)) {
            require(entry.is_regular_file() && !entry.is_symlink(), "flat regular source directory required");
            auto name = entry.path().filename();
            if (name == "LOCK" || name == "LOG" || name.string().rfind("LOG.old.", 0) == 0) continue;
            fs::copy_file(entry.path(), output / name, fs::copy_options::none);
        }
        durable_directory(output);
        double copy_seconds = seconds(start);
        stage("independent_copy_and_sync", start);
        auto copied = inventory(output);
        require(copied.bytes == original.bytes, "copied native byte count mismatch");
        start = Clock::now();
        Identity before = readonly_identity(output);
        guard(before, expected_raw, expected_canonical);
        double precheck_seconds = seconds(start);
        stage("pre_recompression_full_identity", start);

        rocksdb::ConfigOptions config;
        config.ignore_unknown_options = false;
        config.ignore_unsupported_options = false;
        rocksdb::DBOptions db_options;
        std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
        checked(rocksdb::LoadLatestOptions(config, output.string(), &db_options, &descriptors));
        require(descriptors.size() == 1 && descriptors[0].name == rocksdb::kDefaultColumnFamilyName,
                "exactly one default column family required");
        require(db_options.db_paths.empty() && db_options.wal_dir.empty() && db_options.db_log_dir.empty(),
                "external database/WAL/log paths are not supported");
        auto& family = descriptors[0].options;
        require(family.cf_paths.empty(), "external column-family paths are not supported");
        require(family.comparator && std::string(family.comparator->Name()) == "leveldb.BytewiseComparator",
                "native bytewise comparator required");
        require(!family.merge_operator && !family.compaction_filter && !family.compaction_filter_factory,
                "custom merging or compaction filters are not supported");
        auto* loaded_table = family.table_factory->GetOptions<rocksdb::BlockBasedTableOptions>();
        require(loaded_table, "LoadLatestOptions did not recover BlockBasedTable options");
        std::string loaded_table_options;
        checked(family.table_factory->GetOptionString(config, &loaded_table_options));
        auto table = *loaded_table;
        uint64_t original_block_bytes = table.block_size;
        std::string loaded_filter_name = table.filter_policy ? table.filter_policy->GetId() : "nullptr";
        // The serialized Bloom policy name omits its numeric configuration and
        // LoadLatestOptions does not rehydrate its pointer. Both source builders
        // explicitly use fullBloomFilterBits=10; do not silently drop that filter.
        table.filter_policy.reset(rocksdb::NewBloomFilterPolicy(source_bloom_bits, false));
        std::string filter_name = table.filter_policy->GetId();
        if (block_bytes) table.block_size = block_bytes;
        family.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
        std::string requested_table_options;
        checked(family.table_factory->GetOptionString(config, &requested_table_options));
        family.compression = rocksdb::kZSTD;
        family.compression_per_level.assign(family.num_levels, rocksdb::kZSTD);
        family.bottommost_compression = rocksdb::kZSTD;
        // This control schedules one explicit full rewrite, not background races.
        bool original_disable_auto = family.disable_auto_compactions;
        family.disable_auto_compactions = true;
        db_options.create_if_missing = false;
        db_options.create_missing_column_families = false;
        db_options.error_if_exists = false; // Opening an intentional existing copy.
        start = Clock::now();
        auto io_before = process_io();
        std::unique_ptr<rocksdb::DB> database;
        std::vector<rocksdb::ColumnFamilyHandle*> handles;
        checked(rocksdb::DB::Open(db_options, output.string(), descriptors, &handles, &database));
        require(handles.size() == 1, "opened unexpected column families");
        rocksdb::CompactRangeOptions compact;
        compact.exclusive_manual_compaction = true;
        compact.bottommost_level_compaction = rocksdb::BottommostLevelCompaction::kForce;
        compact.allow_write_stall = true;
        checked(database->CompactRange(compact, handles[0], nullptr, nullptr));
        rocksdb::WaitForCompactOptions wait;
        wait.wait_for_purge = true;
        checked(database->WaitForCompact(wait));
        std::string properties = table_properties(database.get());
        checked(database->DestroyColumnFamilyHandle(handles[0]));
        handles.clear();
        checked(database->Close());
        database.reset();
        double compact_close_seconds = seconds(start);
        stage("forced_zstd_open_compact_close", start);
        auto sync_start = Clock::now();
        durable_directory(output);
        double output_sync_seconds = seconds(sync_start);
        stage("recompression_output_sync", sync_start);
        auto io_after = process_io();
        double recompression_seconds = seconds(start);
        stage("forced_zstd_recompression_open_close_sync", start);
        auto recompressed = inventory(output);
        start = Clock::now();
        Identity after = readonly_identity(output);
        guard(after, expected_raw, expected_canonical);
        require(after.keys == before.keys && after.frames == before.frames
                && after.key_bytes == before.key_bytes && after.value_bytes == before.value_bytes,
                "recompression logical counts changed");
        double postcheck_seconds = seconds(start);
        stage("post_recompression_full_identity", start);
        auto final_inventory = inventory(output);
        require(final_inventory.json == recompressed.json, "post-recompression readonly identity changed native files");
        auto final_original = inventory(source);
        require(final_original.json == original.json, "original database native metadata changed");
        struct rusage usage{};
        ::getrusage(RUSAGE_SELF, &usage);
        std::ofstream stats(argv[5]);
        require(stats.good(), "cannot create stats output");
        stats << "{\n\"status\":\"PASS_FORCED_ZSTD_RECOMPRESSION_EXACT_KV\",\n"
              << "\"source_database\":" << quote(source.string()) << ",\n"
              << "\"output_database\":" << quote(output.string()) << ",\n"
              << "\"original_source_native_bytes\":" << original.bytes << ",\n"
              << "\"copied_native_bytes\":" << copied.bytes << ",\n"
              << "\"recompressed_native_bytes\":" << recompressed.bytes << ",\n"
              << "\"recompressed_allocated_bytes\":" << recompressed.allocated_bytes << ",\n"
              << "\"independent_copy_seconds\":" << copy_seconds << ",\n"
              << "\"pre_identity_seconds\":" << precheck_seconds << ",\n"
              << "\"recompression_open_close_sync_seconds\":" << recompression_seconds << ",\n"
              << "\"recompression_open_compact_close_seconds\":" << compact_close_seconds << ",\n"
              << "\"recompression_output_sync_seconds\":" << output_sync_seconds << ",\n"
              << "\"post_identity_seconds\":" << postcheck_seconds << ",\n"
              << "\"total_control_seconds\":" << seconds(total_start) << ",\n"
              << "\"requested_block_bytes\":" << block_bytes << ",\n"
              << "\"loaded_original_block_bytes\":" << original_block_bytes << ",\n"
              << "\"actual_output_block_target_bytes\":" << table.block_size << ",\n"
              << "\"loaded_filter_policy_id\":" << quote(loaded_filter_name) << ",\n"
              << "\"source_proven_full_bloom_bits\":" << source_bloom_bits << ",\n"
              << "\"actual_output_filter_policy_id\":" << quote(filter_name) << ",\n"
              << "\"loaded_table_options\":" << quote(loaded_table_options) << ",\n"
              << "\"requested_table_options\":" << quote(requested_table_options) << ",\n"
              << "\"loaded_original_disable_auto_compactions\":" << (original_disable_auto ? "true" : "false") << ",\n"
              << "\"control_auto_compactions_disabled\":true,\n"
              << "\"loaded_num_levels\":" << family.num_levels << ",\n"
              << "\"before_identity\":" << before.json() << ",\n"
              << "\"after_identity\":" << after.json() << ",\n"
              << "\"actual_sst_properties\":" << properties << ",\n"
              << "\"recompression_process_io\":" << io_difference(io_before, io_after) << ",\n"
              << "\"self_peak_rss_kib_all_phases\":" << usage.ru_maxrss << ",\n"
              << "\"original_native_metadata_unchanged\":true,\n"
              << "\"original_files\":" << original.json << ",\n"
              << "\"output_files\":" << recompressed.json << ",\n"
              << "\"metric_scope\":\"P1 recompressed representation only; copy and verification separated; recompression time is not source-to-image T_build; original never opened writable\",\n"
              << "\"load_options_scope\":\"Strict LoadLatestOptions recovers serialized DB/CF/block options. Full Bloom10 is restored explicitly from both qualified builder sources because the loader returns a null pointer. Other documented pointer-only options use library defaults; bytewise comparator and no custom merge/filter required\"\n}\n";
        stats.close();
        require(stats.good(), "cannot finish stats output");
        std::cout << "{\"kind\":\"SUMMARY\",\"status\":\"PASS_FORCED_ZSTD_RECOMPRESSION_EXACT_KV\",\"native_bytes\":"
                  << recompressed.bytes << ",\"stats\":" << quote(argv[5]) << "}" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "recompression error: " << error.what() << '\n';
        return 1;
    }
}
