#include <ldns/ldns.h>
#include <openssl/evp.h>
#include <zstd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<unsigned char>;

void require(bool condition, const std::string& error) {
    if (!condition) throw std::runtime_error(error);
}

double elapsed(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

std::string json_quote(const std::string& text) {
    std::string out = "\"";
    for (unsigned char byte : text) {
        if (byte == '"' || byte == '\\') { out += '\\'; out += byte; }
        else if (byte >= 32 && byte < 127) out += byte;
        else {
            static const char* hex = "0123456789abcdef";
            out += "\\u00"; out += hex[byte >> 4]; out += hex[byte & 15];
        }
    }
    return out + '"';
}

class Hash {
public:
    Hash() : context_(EVP_MD_CTX_new()) {
        require(context_, "cannot allocate SHA256 context");
        reset();
    }
    ~Hash() { EVP_MD_CTX_free(context_); }
    Hash(const Hash&) = delete;
    Hash& operator=(const Hash&) = delete;
    Hash(Hash&& other) noexcept : context_(other.context_) { other.context_ = nullptr; }
    Hash& operator=(Hash&& other) noexcept {
        if (this != &other) { EVP_MD_CTX_free(context_); context_ = other.context_; other.context_ = nullptr; }
        return *this;
    }
    void add(const void* data, size_t length) {
        require(EVP_DigestUpdate(context_, data, length) == 1, "cannot update SHA256");
    }
    void reset() { require(EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1, "cannot initialize SHA256"); }
    std::string finish() {
        unsigned char digest[32]; unsigned length = 0;
        require(EVP_DigestFinal_ex(context_, digest, &length) == 1 && length == 32, "cannot finalize SHA256");
        static const char* digits = "0123456789abcdef";
        std::string result(64, '0');
        for (size_t i = 0; i < 32; ++i) { result[2*i] = digits[digest[i] >> 4]; result[2*i+1] = digits[digest[i] & 15]; }
        return result;
    }
private:
    EVP_MD_CTX* context_;
};

std::map<std::string, uint64_t> io() {
    std::ifstream input("/proc/self/io");
    require(input.good(), "cannot read Linux process IO");
    std::map<std::string, uint64_t> result;
    std::string key; uint64_t value;
    while (input >> key >> value) { if (!key.empty() && key.back() == ':') key.pop_back(); result[key] = value; }
    require(result.count("write_bytes") && result.count("cancelled_write_bytes"), "missing Linux process IO fields");
    return result;
}

std::string io_delta(const std::map<std::string,uint64_t>& before,
                     const std::map<std::string,uint64_t>& after) {
    std::string result = "{"; bool comma = false;
    for (const auto& entry : after) {
        auto old = before.find(entry.first);
        require(old != before.end() && entry.second >= old->second, "Linux IO counter decreased");
        if (comma) result += ',';
        comma = true;
        result += json_quote(entry.first) + ':' + std::to_string(entry.second - old->second);
    }
    return result + '}';
}

void sync_file(FILE* file, const char* label) {
    require(std::fflush(file) == 0, std::string("cannot flush ") + label);
    require(::fsync(::fileno(file)) == 0, std::string("cannot sync ") + label);
}

uint32_t decimal(const char* text) {
    require(text && *text, "missing decimal TTL");
    uint64_t value = 0;
    for (const unsigned char* byte = reinterpret_cast<const unsigned char*>(text); *byte; ++byte) {
        require(*byte >= '0' && *byte <= '9', "non-decimal TTL");
        value = value * 10 + *byte - '0';
        require(value <= UINT32_MAX, "TTL overflow");
    }
    return value;
}

bool whitespace(unsigned char value) { return value == ' ' || value == '\t' || value == '\r' || value == '\n'; }

std::string ns_target(const char* remainder, uint64_t& escaped_names) {
    require(remainder, "missing NS target");
    while (whitespace(*remainder)) ++remainder;
    const char* end = remainder;
    while (*end && !whitespace(*end)) {
        if (*end == '\\') { require(end[1], "truncated NS escape"); ++end; }
        ++end;
    }
    std::string text(remainder, end - remainder);
    while (whitespace(*end)) ++end;
    require(*end == 0 && !text.empty() && text.size() <= 4096, "NS target has unsupported trailing fields or length");
    size_t backslashes = 0;
    if (text.back() == '.')
        for (size_t i = text.size() - 1; i > 0 && text[i-1] == '\\'; --i) ++backslashes;
    require(text.back() == '.' && backslashes % 2 == 0, "NS target must be absolute");
    if (text.find('\\') != std::string::npos) {
        ++escaped_names;
        ldns_rdf* name = ldns_dname_new_frm_str(text.c_str());
        require(name != nullptr, "ldns rejected escaped NS target");
        ldns_dname2canonical(name);
        std::string wire(reinterpret_cast<const char*>(ldns_rdf_data(name)), ldns_rdf_size(name));
        ldns_rdf_deep_free(name);
        require(!wire.empty() && wire.size() <= 255 && wire.back() == 0, "invalid escaped NS name wire");
        return wire;
    }
    if (text == ".") return std::string(1, '\0');
    std::string wire;
    size_t start = 0;
    while (start < text.size()) {
        size_t dot = text.find('.', start);
        require(dot != std::string::npos && dot > start && dot-start <= 63, "invalid NS target label length");
        wire.push_back(static_cast<char>(dot-start));
        for (size_t i = start; i < dot; ++i) {
            unsigned char byte = text[i];
            require(byte != ';' && byte != '(' && byte != ')' && byte != '"', "unsupported unescaped NS target syntax");
            if (byte >= 'A' && byte <= 'Z') byte += 'a' - 'A';
            wire.push_back(static_cast<char>(byte));
        }
        start = dot + 1;
    }
    wire.push_back('\0');
    require(wire.size() <= 255, "NS target exceeds wire name length");
    return wire;
}

struct ScanResult {
    uint64_t source_bytes = 0, rr_occurrences = 0, ns_occurrences = 0;
    uint64_t total_rdata_bytes = 0, spool_bytes = 0, escaped_ns_names = 0;
    std::string source_sha256;
    struct stat identity{};
};

ScanResult scan(const fs::path& source, const fs::path& spool, const std::string& expected_sha) {
    FILE* input = std::fopen(source.c_str(), "rb");
    require(input, "cannot open source read-only");
    FILE* output = std::fopen(spool.c_str(), "wbx");
    require(output, "cannot create exclusive NS spool");
    ScanResult result;
    require(::fstat(::fileno(input), &result.identity) == 0, "cannot stat source");
    Hash source_hash;
    Bytes buffer(8 << 20);
    std::string carry;
    std::array<char, 512> hex_line{};
    static const char* digits = "0123456789abcdef";
    auto line = [&](char* text) {
        char* state = nullptr;
        char* owner = ::strtok_r(text, " \t\r\n", &state);
        if (!owner) return;
        require(owner[0] != ';' && owner[0] != '$', "requires flattened RR lines without directives/comments");
        size_t owner_length = std::strlen(owner);
        require(owner_length && owner[owner_length-1] == '.', "requires absolute-owner flattened RR lines");
        decimal(::strtok_r(nullptr, " \t\r\n", &state));
        char* klass = ::strtok_r(nullptr, " \t\r\n", &state);
        char* type = ::strtok_r(nullptr, " \t\r\n", &state);
        require(klass && ::strcasecmp(klass, "IN") == 0 && type && *type, "requires IN TYPE flattened RR layout");
        require(state && *state, "missing RDATA field");
        ++result.rr_occurrences;
        if (::strcasecmp(type, "NS") != 0) return;
        std::string wire = ns_target(state, result.escaped_ns_names);
        ++result.ns_occurrences;
        result.total_rdata_bytes += wire.size();
        for (size_t i = 0; i < wire.size(); ++i) {
            unsigned char byte = wire[i];
            hex_line[2*i] = digits[byte >> 4]; hex_line[2*i+1] = digits[byte & 15];
        }
        size_t length = wire.size()*2;
        hex_line[length++] = '\n';
        require(std::fwrite(hex_line.data(), 1, length, output) == length, "NS spool write failed");
        result.spool_bytes += length;
    };
    uint64_t next_progress = 2ULL << 30;
    while (size_t length = std::fread(buffer.data(), 1, buffer.size(), input)) {
        source_hash.add(buffer.data(), length);
        result.source_bytes += length;
        char* cursor = reinterpret_cast<char*>(buffer.data());
        char* end = cursor + length;
        while (cursor < end) {
            char* newline = static_cast<char*>(std::memchr(cursor, '\n', end-cursor));
            size_t part_length = newline ? static_cast<size_t>(newline-cursor) : static_cast<size_t>(end-cursor);
            require(carry.size() + part_length <= (1 << 20), "source line exceeds 1MiB bound");
            require(std::memchr(cursor, 0, part_length) == nullptr, "source contains NUL byte");
            if (!newline) { carry.append(cursor, part_length); break; }
            *newline = 0;
            if (carry.empty()) line(cursor);
            else { carry.append(cursor, part_length); line(carry.data()); carry.clear(); }
            cursor = newline + 1;
        }
        if (result.source_bytes >= next_progress) {
            std::cerr << "PROGRESS {\"stage\":\"scan_ns_spool\",\"source_bytes\":" << result.source_bytes
                      << ",\"ns_occurrences\":" << result.ns_occurrences << "}\n";
            next_progress += 2ULL << 30;
        }
    }
    require(!std::ferror(input), "source read failed");
    if (!carry.empty()) line(carry.data());
    struct stat after{};
    require(::fstat(::fileno(input), &after) == 0, "cannot restat source");
    require(result.identity.st_dev == after.st_dev && result.identity.st_ino == after.st_ino &&
            result.identity.st_size == after.st_size && result.identity.st_mtim.tv_sec == after.st_mtim.tv_sec &&
            result.identity.st_mtim.tv_nsec == after.st_mtim.tv_nsec && result.identity.st_ctim.tv_sec == after.st_ctim.tv_sec &&
            result.identity.st_ctim.tv_nsec == after.st_ctim.tv_nsec && result.source_bytes == static_cast<uint64_t>(after.st_size),
            "source identity changed during scan");
    require(std::fclose(input) == 0, "source close failed");
    result.source_sha256 = source_hash.finish();
    require(result.source_sha256 == expected_sha, "complete source SHA256 does not match expected identity");
    sync_file(output, "NS spool");
    require(std::fclose(output) == 0, "NS spool close failed");
    require(fs::file_size(spool) == result.spool_bytes, "NS spool size mismatch");
    return result;
}

void sort_unique(const fs::path& input, const fs::path& output, const fs::path& directory) {
    pid_t child = ::fork();
    require(child >= 0, "cannot fork GNU sort");
    if (!child) {
        ::setenv("LC_ALL", "C", 1);
        ::execlp("sort", "sort", "-u", "--parallel=1", "--batch-size=4", "-S4M", "-T", directory.c_str(),
                 "-o", output.c_str(), input.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "GNU unique sort failed");
    int descriptor = ::open(output.c_str(), O_RDONLY);
    require(descriptor >= 0 && ::fsync(descriptor) == 0, "cannot sync sorted unique scratch");
    require(::close(descriptor) == 0, "cannot close sorted unique scratch");
}

void varint(Bytes& bytes, uint64_t value) {
    while (value >= 128) { bytes.push_back((value & 127) | 128); value >>= 7; }
    bytes.push_back(value);
}

class DictionaryCodec {
public:
    void add(const std::string& wire) {
        Bytes record = front_code(wire, previous_);
        if (!pending_.empty() && pending_.size() + record.size() > 65536) {
            flush(); record = front_code(wire, "");
        }
        require(pending_.size() + record.size() <= 65536, "dictionary decoded block bound exceeded");
        pending_.insert(pending_.end(), record.begin(), record.end());
        expected_names_.add(wire.data(), wire.size());
        previous_ = wire;
        ++pending_names_;
    }
    void finish() { flush(); }
    uint64_t blocks = 0, raw_frontcoded_bytes = 0, compressed_payload_bytes = 0;
    uint64_t maximum_decoded_block = 0, dictionary_entries = 0;
private:
    static Bytes front_code(const std::string& wire, const std::string& previous) {
        size_t common = 0;
        while (common < wire.size() && common < previous.size() && wire[common] == previous[common]) ++common;
        Bytes record;
        varint(record, common); varint(record, wire.size() - common);
        record.insert(record.end(), wire.begin()+common, wire.end());
        return record;
    }
    void flush() {
        if (pending_.empty()) return;
        Bytes compressed(ZSTD_compressBound(pending_.size()));
        size_t encoded = ZSTD_compress(compressed.data(), compressed.size(), pending_.data(), pending_.size(), 3);
        require(!ZSTD_isError(encoded), "dictionary Zstd compression failed");
        Bytes decoded(pending_.size());
        size_t decoded_size = ZSTD_decompress(decoded.data(), decoded.size(), compressed.data(), encoded);
        require(!ZSTD_isError(decoded_size) && decoded_size == pending_.size() && decoded == pending_, "dictionary block roundtrip mismatch");
        size_t cursor = 0;
        uint64_t decoded_names = 0;
        std::string previous;
        Hash recovered_names;
        auto read_varint = [&]() {
            uint64_t value = 0;
            for (unsigned shift = 0; shift < 64; shift += 7) {
                require(cursor < decoded.size(), "truncated dictionary front code");
                unsigned byte = decoded[cursor++];
                require(shift < 63 || byte <= 1, "dictionary varint overflow");
                value |= static_cast<uint64_t>(byte & 127) << shift;
                if (!(byte & 128)) return value;
            }
            throw std::runtime_error("dictionary varint too long");
        };
        while (cursor < decoded.size()) {
            uint64_t common = read_varint();
            uint64_t suffix = read_varint();
            require(common <= previous.size() && suffix <= decoded.size() - cursor && common + suffix <= 255,
                    "invalid decoded dictionary front code");
            std::string wire = previous.substr(0, common);
            wire.append(reinterpret_cast<const char*>(decoded.data() + cursor), suffix);
            cursor += suffix;
            recovered_names.add(wire.data(), wire.size());
            previous = std::move(wire);
            ++decoded_names;
        }
        require(decoded_names == pending_names_ && recovered_names.finish() == expected_names_.finish(),
                "dictionary front-code inverse mismatch");
        expected_names_.reset();
        ++blocks;
        dictionary_entries += pending_names_;
        raw_frontcoded_bytes += pending_.size();
        compressed_payload_bytes += encoded;
        maximum_decoded_block = std::max<uint64_t>(maximum_decoded_block, pending_.size());
        pending_.clear(); previous_.clear(); pending_names_ = 0;
    }
    Bytes pending_;
    std::string previous_;
    uint64_t pending_names_ = 0;
    Hash expected_names_;
};

struct UniqueResult {
    uint64_t names = 0, wire_bytes = 0;
    std::string unique_wire_concat_sha256;
    DictionaryCodec dictionary;
};

UniqueResult aggregate(const fs::path& path) {
    FILE* input = std::fopen(path.c_str(), "rb");
    require(input, "cannot read unique NS scratch");
    std::array<char, 514> line{};
    std::string previous;
    Hash unique_hash;
    UniqueResult result;
    while (std::fgets(line.data(), line.size(), input)) {
        size_t length = std::strlen(line.data());
        require(length >= 3 && line[length-1] == '\n' && length % 2 == 1 && length <= 511, "malformed unique hex row");
        --length;
        std::string text(line.data(), length);
        require(previous.empty() || previous < text, "unique scratch is not strictly sorted");
        previous = text;
        std::string wire(length/2, '\0');
        auto nibble = [](unsigned char value) {
            require((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'), "non-lowercase unique hex");
            return value <= '9' ? value-'0' : value-'a'+10;
        };
        for (size_t i = 0; i < wire.size(); ++i) wire[i] = static_cast<char>((nibble(text[2*i]) << 4) | nibble(text[2*i+1]));
        size_t cursor = 0;
        while (cursor < wire.size() && wire[cursor]) {
            size_t label = static_cast<unsigned char>(wire[cursor++]);
            require(label <= 63 && label <= wire.size() - cursor, "invalid canonical NS name wire");
            cursor += label;
        }
        require(cursor+1 == wire.size() && wire[cursor] == 0, "invalid canonical NS root terminator");
        ++result.names;
        result.wire_bytes += wire.size();
        unique_hash.add(wire.data(), wire.size());
        result.dictionary.add(wire);
    }
    require(!std::ferror(input) && std::fclose(input) == 0, "unique scratch read/close failed");
    result.dictionary.finish();
    require(result.dictionary.dictionary_entries == result.names, "dictionary entry count mismatch");
    result.unique_wire_concat_sha256 = unique_hash.finish();
    return result;
}

int main(int argc, char** argv) {
    try {
        require(argc == 5, "usage: com_ns_reuse SOURCE OUTPUT_JSON FRESH_WORK EXPECTED_SOURCE_SHA256");
        auto total_start = Clock::now();
        auto operation_io = io();
        fs::path source = fs::canonical(argv[1]);
        fs::path output = fs::absolute(argv[2]).lexically_normal();
        fs::path work = fs::absolute(argv[3]).lexically_normal();
        require(!fs::exists(output) && !fs::exists(work), "output and work must be fresh");
        require(std::strlen(argv[4]) == 64, "expected source SHA256 must be 64 lowercase hex characters");
        fs::create_directories(work / "sort");
        fs::create_directories(output.parent_path());
        fs::path spool = work / "ns_wire.hex";
        fs::path unique = work / "ns_unique.hex";
        std::vector<std::string> stages;
        auto emit_stage = [&](const char* name, Clock::time_point start, const std::map<std::string,uint64_t>& before) {
            std::string stage = "{\"stage\":" + json_quote(name) + ",\"seconds\":" + std::to_string(elapsed(start)) +
                ",\"process_io_delta\":" + io_delta(before, io()) + '}';
            stages.push_back(stage);
            std::cerr << "STAGE " << stage << '\n';
        };
        auto start = Clock::now(); auto stage_io = io();
        ScanResult scanned = scan(source, spool, argv[4]);
        emit_stage("scan_hash_ns_spool_fsync", start, stage_io);
        start = Clock::now(); stage_io = io();
        sort_unique(spool, unique, work/"sort");
        uint64_t unique_scratch_bytes = fs::file_size(unique);
        emit_stage("bounded_external_sort_unique_fsync", start, stage_io);
        start = Clock::now(); stage_io = io();
        UniqueResult aggregated = aggregate(unique);
        emit_stage("stream_unique_frontcode_block_zstd_verify", start, stage_io);
        require(aggregated.names <= scanned.ns_occurrences && aggregated.wire_bytes <= scanned.total_rdata_bytes,
                "distinct aggregate exceeds occurrence aggregate");
        unsigned reference_bytes = 0;
        for (uint64_t maximum_id = aggregated.names ? aggregated.names-1 : 0; maximum_id; maximum_id >>= 8) ++reference_bytes;
        uint64_t references = scanned.ns_occurrences * reference_bytes;
        start = Clock::now(); stage_io = io();
        require(fs::remove(spool) && fs::remove(unique), "cannot remove owned scratch files");
        require(fs::is_empty(work/"sort"), "GNU sort left unexpected scratch files");
        fs::remove(work/"sort"); fs::remove(work);
        emit_stage("remove_owned_scratch", start, stage_io);
        struct rusage self{}, children{};
        require(::getrusage(RUSAGE_SELF, &self) == 0 && ::getrusage(RUSAGE_CHILDREN, &children) == 0, "cannot read resource receipt");
        std::string summary = "{\"status\":\"PASS_FULL_SOURCE_NS_REUSE_CENSUS\",\"source\":" + json_quote(source.string()) +
            ",\"source_bytes\":" + std::to_string(scanned.source_bytes) + ",\"source_sha256\":" + json_quote(scanned.source_sha256) +
            ",\"source_identity\":{\"device\":" + std::to_string(scanned.identity.st_dev) + ",\"inode\":" + std::to_string(scanned.identity.st_ino) +
            ",\"mtime_seconds\":" + std::to_string(scanned.identity.st_mtim.tv_sec) + ",\"mtime_nanoseconds\":" + std::to_string(scanned.identity.st_mtim.tv_nsec) +
            ",\"ctime_seconds\":" + std::to_string(scanned.identity.st_ctim.tv_sec) + ",\"ctime_nanoseconds\":" + std::to_string(scanned.identity.st_ctim.tv_nsec) + "}" +
            ",\"rr_occurrences\":" + std::to_string(scanned.rr_occurrences) + ",\"ns_rr_occurrences\":" + std::to_string(scanned.ns_occurrences) +
            ",\"ns_rdata_wire_bytes\":" + std::to_string(scanned.total_rdata_bytes) + ",\"unique_ns_domains\":" + std::to_string(aggregated.names) +
            ",\"unique_ns_rdata_wire_bytes\":" + std::to_string(aggregated.wire_bytes) + ",\"escaped_ns_occurrences\":" + std::to_string(scanned.escaped_ns_names) +
            ",\"unique_ns_wire_concat_sha256\":" + json_quote(aggregated.unique_wire_concat_sha256) +
            ",\"fixed_id_reference_bytes_each\":" + std::to_string(reference_bytes) + ",\"fixed_id_reference_payload_bytes\":" + std::to_string(references) +
            ",\"optimistic_unique_wire_plus_fixed_ids_bytes\":" + std::to_string(aggregated.wire_bytes + references) +
            ",\"dictionary_component\":{\"codec\":\"Zstd3\",\"order\":\"canonical NS wire unsigned-lexicographic\",\"block_target_decoded_bytes\":65536,\"blocks\":" + std::to_string(aggregated.dictionary.blocks) +
            ",\"frontcoded_decoded_bytes\":" + std::to_string(aggregated.dictionary.raw_frontcoded_bytes) +
            ",\"maximum_decoded_block_bytes\":" + std::to_string(aggregated.dictionary.maximum_decoded_block) +
            ",\"compressed_payload_bytes\":" + std::to_string(aggregated.dictionary.compressed_payload_bytes) +
            ",\"block_frames_bytes\":" + std::to_string(aggregated.dictionary.blocks*12) +
            ",\"framed_compressed_component_bytes\":" + std::to_string(aggregated.dictionary.compressed_payload_bytes + aggregated.dictionary.blocks*12) +
            ",\"optional_block_offsets_bytes\":" + std::to_string(aggregated.dictionary.blocks*8) + ",\"block_codec_roundtrip_verified\":true}" +
            ",\"scratch\":{\"ns_hex_spool_bytes\":" + std::to_string(scanned.spool_bytes) + ",\"unique_hex_bytes\":" + std::to_string(unique_scratch_bytes) +
            ",\"retained_payload_bytes\":0,\"sort_buffer_bytes\":4194304,\"sort_parallel\":1,\"sort_fan_in\":4,\"peak_scope\":\"separate observer samples visible files and open-deleted files\"}" +
            ",\"self_peak_rss_kib\":" + std::to_string(self.ru_maxrss) + ",\"child_peak_rss_kib\":" + std::to_string(children.ru_maxrss) +
            ",\"child_input_blocks_512\":" + std::to_string(children.ru_inblock) + ",\"child_output_blocks_512\":" + std::to_string(children.ru_oublock) +
            ",\"process_io_delta\":" + io_delta(operation_io, io()) + ",\"total_seconds\":" + std::to_string(elapsed(total_start)) +
            ",\"scope\":\"NS RDATA component screening only; excludes pool directories, owner/type/class/TTL, update mappings, generations and full-image integration; no full-image savings claim\",\"stages\":[";
        for (size_t i = 0; i < stages.size(); ++i) { if (i) summary += ','; summary += stages[i]; }
        summary += "]}";
        FILE* receipt = std::fopen(output.c_str(), "wbx");
        require(receipt, "cannot create exclusive aggregate receipt");
        require(std::fwrite(summary.data(), 1, summary.size(), receipt) == summary.size() && std::fputc('\n', receipt) != EOF, "cannot write aggregate receipt");
        sync_file(receipt, "aggregate receipt");
        require(std::fclose(receipt) == 0, "aggregate receipt close failed");
        std::cout << "SUMMARY " << summary << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CENSUS_ERROR " << error.what() << '\n';
        return 1;
    }
}
