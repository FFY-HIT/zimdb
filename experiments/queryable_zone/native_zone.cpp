#include <ldns/ldns.h>
#include <lz4.h>
#include <zstd.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using Bytes = std::vector<uint8_t>;

namespace {

constexpr uint32_t kVersion = 1;
constexpr uint32_t kPoolFlag = 1;
constexpr uint32_t kFrontFlag = 2;
constexpr uint32_t kPackedIndexFlag = 4;
constexpr uint32_t kCowIndexFlag = 8;
constexpr uint32_t kCompactKeyFlag = 16;
constexpr uint32_t kNsec3NextKeyFlag = 32;
constexpr uint32_t kIndexRestartInterval = 16;
constexpr size_t kPageTarget = 65536;
constexpr size_t kMaxPage = 262144;
constexpr size_t kMaxKey = 512;
constexpr size_t kMaxWire = 255 + 10 + 65535;
constexpr size_t kMaxSortLine = 2 * (kMaxWire + kMaxKey) + 4;

#pragma pack(push, 1)
struct ImageHeader {
    char magic[8];
    uint32_t version;
    uint32_t flags;
    uint64_t page_count;
    uint64_t index_offset;
    uint64_t occurrences;
    uint64_t unique_records;
    uint32_t page_target;
    uint32_t requested_codec;
    uint32_t origin_length;
    uint32_t header_size;
    uint8_t origin[256];
    uint8_t reserved[192];
};

struct PageIndex {
    uint64_t offset;
    uint32_t encoded_size;
    uint32_t decoded_size;
    uint32_t record_count;
    uint16_t first_key_length;
    uint16_t codec;
    uint8_t first_key[kMaxKey];
    uint64_t checksum;
};

struct GenerationHeader {
    char magic[8];
    uint32_t version;
    uint32_t path_length;
    ImageHeader snapshot;
};

struct PackedIndexMeta {
    char magic[8];
    uint64_t data_bytes;
    uint64_t restart_offset;
    uint64_t restart_count;
    uint64_t restart_checksum;
    uint32_t restart_interval;
    uint32_t restart_entry_size;
    uint8_t reserved[16];
};

struct IndexRestart {
    uint64_t offset;
    uint64_t checksum;
};

struct CowRef {
    uint64_t offset;
    uint32_t length;
    uint32_t height;
    uint64_t pages;
    uint64_t checksum;
};

struct CowIndexMeta {
    char magic[8];
    CowRef root;
    uint64_t created_node_bytes;
    uint64_t created_node_count;
    uint64_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(ImageHeader) == 512, "image header layout");
static_assert(sizeof(PageIndex) == 544, "page index layout");
static_assert(sizeof(GenerationHeader) == 528, "generation header layout");
static_assert(sizeof(PackedIndexMeta) == 64, "packed index metadata layout");
static_assert(sizeof(IndexRestart) == 16, "packed restart layout");
static_assert(sizeof(CowRef) == 32, "persistent node reference layout");
static_assert(sizeof(CowIndexMeta) == 64, "persistent index metadata layout");

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void syscheck(bool condition, const std::string& operation) {
    if (!condition) throw std::runtime_error(operation + ": " + std::strerror(errno));
}

double seconds_since(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

std::map<std::string, uint64_t> process_io() {
    std::ifstream input("/proc/self/io");
    require(input.good(), "cannot read process IO counters");
    std::map<std::string, uint64_t> counters;
    std::string key;
    uint64_t value;
    while (input >> key >> value) {
        require(!key.empty() && key.back() == ':', "invalid process IO counter");
        key.pop_back();
        counters.emplace(key, value);
    }
    require(!counters.empty(), "empty process IO counters");
    return counters;
}

std::string json_string(const std::string& value) {
    static const char* digits = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char byte : value) {
        switch (byte) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (byte < 32 || byte >= 127) {
                    out += "\\u00";
                    out += digits[byte >> 4];
                    out += digits[byte & 15];
                } else out += static_cast<char>(byte);
        }
    }
    return out + "\"";
}

std::string hex(const uint8_t* data, size_t length) {
    static const char* digits = "0123456789abcdef";
    std::string out(length * 2, '\0');
    for (size_t i = 0; i < length; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
    return out;
}

std::string hex(const std::string& value) {
    return hex(reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

unsigned hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    throw std::runtime_error("invalid hex digit");
}

std::string unhex(const char* input, size_t length) {
    require(length % 2 == 0, "odd hex length");
    std::string out(length / 2, '\0');
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<char>((hex_digit(input[2 * i]) << 4) | hex_digit(input[2 * i + 1]));
    return out;
}

void put16(Bytes& out, uint16_t value) {
    out.push_back(value & 255);
    out.push_back(value >> 8);
}

void put32(Bytes& out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out.push_back((value >> (8 * i)) & 255);
}

void put64(Bytes& out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out.push_back((value >> (8 * i)) & 255);
}

uint16_t get16(const uint8_t* data, size_t size, size_t& position) {
    require(position <= size && size - position >= 2, "truncated u16");
    uint16_t value = data[position] | static_cast<uint16_t>(data[position + 1]) << 8;
    position += 2;
    return value;
}

uint32_t get32(const uint8_t* data, size_t size, size_t& position) {
    require(position <= size && size - position >= 4, "truncated u32");
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= static_cast<uint32_t>(data[position++]) << (8 * i);
    return value;
}

uint64_t get64(const uint8_t* data, size_t size, size_t& position) {
    require(position <= size && size - position >= 8, "truncated u64");
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= static_cast<uint64_t>(data[position++]) << (8 * i);
    return value;
}

void put_varint(Bytes& out, uint64_t value) {
    do {
        uint8_t byte = value & 127;
        value >>= 7;
        out.push_back(byte | (value ? 128 : 0));
    } while (value);
}

uint64_t get_varint(const uint8_t* data, size_t size, size_t& position) {
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        require(position < size, "truncated varint");
        uint8_t byte = data[position++];
        if (shift == 63) require(byte <= 1, "varint overflow");
        value |= static_cast<uint64_t>(byte & 127) << shift;
        if (!(byte & 128)) return value;
    }
    throw std::runtime_error("varint overflow");
}

uint64_t checksum(const uint8_t* data, size_t length) {
    uint64_t value = 14695981039346656037ULL;
    for (size_t i = 0; i < length; ++i) {
        value ^= data[i];
        value *= 1099511628211ULL;
    }
    return value;
}

uint64_t checksum_continue(uint64_t value, const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        value ^= data[i];
        value *= 1099511628211ULL;
    }
    return value;
}

uint64_t final_index_bytes(const ImageHeader& header) {
    if (header.flags & kCowIndexFlag) return 0;
    if (!(header.flags & kPackedIndexFlag)) {
        require(header.page_count <= std::numeric_limits<uint64_t>::max() / sizeof(PageIndex), "index size overflow");
        return header.page_count * sizeof(PageIndex);
    }
    PackedIndexMeta meta{};
    std::memcpy(&meta, header.reserved, sizeof(meta));
    require(std::memcmp(meta.magic, "ZIMIDX1\0", 8) == 0 && meta.restart_interval == kIndexRestartInterval &&
            meta.restart_entry_size == sizeof(IndexRestart) && meta.restart_offset == meta.data_bytes,
            "invalid packed index metadata");
    require(meta.restart_count <= (std::numeric_limits<uint64_t>::max() - meta.data_bytes) / sizeof(IndexRestart),
            "packed index size overflow");
    return meta.data_bytes + meta.restart_count * sizeof(IndexRestart);
}

size_t wire_name_length(const uint8_t* wire, size_t length) {
    size_t pos = 0;
    while (true) {
        require(pos < length, "truncated wire name");
        unsigned label = wire[pos++];
        require(label <= 63, "compressed or invalid canonical wire name");
        if (label == 0) return pos;
        require(label <= length - pos, "truncated wire label");
        pos += label;
        require(pos <= 255, "wire name too long");
    }
}

std::vector<std::string> wire_labels(const std::string& wire) {
    wire_name_length(reinterpret_cast<const uint8_t*>(wire.data()), wire.size());
    std::vector<std::string> labels;
    size_t pos = 0;
    while (static_cast<uint8_t>(wire[pos])) {
        unsigned length = static_cast<uint8_t>(wire[pos++]);
        labels.emplace_back(wire.data() + pos, length);
        pos += length;
    }
    return labels;
}

std::string name_wire(const std::string& text) {
    ldns_rdf* name = ldns_dname_new_frm_str(text.c_str());
    require(name != nullptr, "invalid domain name " + text);
    ldns_dname2canonical(name);
    std::string wire(reinterpret_cast<const char*>(ldns_rdf_data(name)), ldns_rdf_size(name));
    ldns_rdf_deep_free(name);
    return wire;
}

std::string name_text(const std::string& wire) {
    ldns_rdf* name = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, wire.size(), wire.data());
    require(name != nullptr, "invalid stored domain name");
    char* text = ldns_rdf2str(name);
    require(text != nullptr, "cannot print domain name");
    std::string result(text);
    std::free(text);
    ldns_rdf_deep_free(name);
    return result;
}

std::string make_key(const std::string& owner, const std::string& origin, uint32_t flags = 0) {
    auto labels = wire_labels(owner);
    auto origin_labels = wire_labels(origin);
    require(labels.size() >= origin_labels.size(), "owner outside origin");
    size_t relative = labels.size() - origin_labels.size();
    for (size_t i = 0; i < origin_labels.size(); ++i)
        require(labels[relative + i] == origin_labels[i], "owner outside origin");
    std::string key;
    for (size_t i = relative; i > 0; --i) {
        for (uint8_t byte : labels[i - 1]) {
            if (flags & kCompactKeyFlag) {
                if (byte < 254) key.push_back(static_cast<char>(byte + 1));
                else {
                    key.push_back(static_cast<char>(255));
                    key.push_back(static_cast<char>(byte - 253));
                }
            } else {
                key.push_back(static_cast<char>((byte >> 4) + 1));
                key.push_back(static_cast<char>((byte & 15) + 1));
            }
        }
        key.push_back('\0');
    }
    require(key.size() <= kMaxKey, "canonical key too long");
    return key;
}

std::string owner_from_key(const std::string& key, const std::string& origin, uint32_t flags = 0) {
    std::vector<std::string> labels;
    size_t pos = 0;
    while (pos < key.size()) {
        std::string label;
        while (pos < key.size() && key[pos] != 0) {
            if (flags & kCompactKeyFlag) {
                unsigned byte = static_cast<uint8_t>(key[pos++]);
                if (byte == 255) {
                    require(pos < key.size(), "truncated compact key escape");
                    unsigned escaped = static_cast<uint8_t>(key[pos++]);
                    require(escaped == 1 || escaped == 2, "invalid compact key escape");
                    label.push_back(static_cast<char>(253 + escaped));
                } else label.push_back(static_cast<char>(byte - 1));
            } else {
                require(pos + 1 < key.size(), "truncated stored key");
                unsigned high = static_cast<uint8_t>(key[pos++]);
                unsigned low = static_cast<uint8_t>(key[pos++]);
                require(high >= 1 && high <= 16 && low >= 1 && low <= 16, "invalid stored key nibble");
                label.push_back(static_cast<char>(((high - 1) << 4) | (low - 1)));
            }
        }
        require(pos < key.size() && key[pos] == 0 && !label.empty() && label.size() <= 63,
                "invalid stored key label");
        ++pos;
        labels.push_back(std::move(label));
    }
    std::string owner;
    for (auto it = labels.rbegin(); it != labels.rend(); ++it) {
        owner.push_back(static_cast<char>(it->size()));
        owner += *it;
    }
    owner += origin;
    require(owner.size() <= 255, "decoded owner too long");
    return owner;
}

bool byte_less(const std::string& left, const std::string& right) {
    size_t n = std::min(left.size(), right.size());
    int comparison = n ? std::memcmp(left.data(), right.data(), n) : 0;
    return comparison < 0 || (comparison == 0 && left.size() < right.size());
}

struct Record {
    std::string key;
    std::string rdata;
    uint16_t type = 0;
    uint16_t klass = 0;
    uint32_t ttl = 0;
    uint64_t multiplicity = 1;
};

Record record_from_wire(const std::string& wire, const std::string& origin, uint32_t flags = 0) {
    require(wire.size() <= kMaxWire, "RR exceeds protocol bound");
    size_t owner_size = wire_name_length(reinterpret_cast<const uint8_t*>(wire.data()), wire.size());
    require(wire.size() - owner_size >= 10, "truncated RR header");
    const uint8_t* header = reinterpret_cast<const uint8_t*>(wire.data() + owner_size);
    Record result;
    result.key = make_key(wire.substr(0, owner_size), origin, flags);
    result.type = (header[0] << 8) | header[1];
    result.klass = (header[2] << 8) | header[3];
    result.ttl = (static_cast<uint32_t>(header[4]) << 24) | (static_cast<uint32_t>(header[5]) << 16) |
                 (header[6] << 8) | header[7];
    size_t rdata_length = (header[8] << 8) | header[9];
    require(rdata_length == wire.size() - owner_size - 10, "RR RDLENGTH mismatch");
    result.rdata.assign(wire.data() + owner_size + 10, rdata_length);
    return result;
}

std::string record_wire(const Record& record, const std::string& origin,
                        const std::string* synthesized_owner = nullptr, uint32_t flags = 0) {
    std::string owner = synthesized_owner ? *synthesized_owner : owner_from_key(record.key, origin, flags);
    std::string wire = owner;
    wire.push_back(record.type >> 8);
    wire.push_back(record.type & 255);
    wire.push_back(record.klass >> 8);
    wire.push_back(record.klass & 255);
    for (int shift = 24; shift >= 0; shift -= 8) wire.push_back((record.ttl >> shift) & 255);
    require(record.rdata.size() <= 65535, "RDATA exceeds protocol bound");
    wire.push_back(record.rdata.size() >> 8);
    wire.push_back(record.rdata.size() & 255);
    wire += record.rdata;
    return wire;
}

bool nsec3_next_position(const std::string& rdata, size_t& hash_start) {
    if (rdata.size() < 6) return false;
    size_t hash_length_position = 5 + static_cast<uint8_t>(rdata[4]);
    if (hash_length_position >= rdata.size() || static_cast<uint8_t>(rdata[hash_length_position]) != 20)
        return false;
    hash_start = hash_length_position + 1;
    return rdata.size() - hash_start >= 20;
}

std::string base32hex_hash(const char* hash) {
    static const char* alphabet = "0123456789abcdefghijklmnopqrstuv";
    std::string label(32, '\0');
    for (size_t group = 0; group < 32; ++group) {
        unsigned value = 0;
        for (unsigned bit = 0; bit < 5; ++bit) {
            size_t position = group * 5 + bit;
            value = (value << 1) | ((static_cast<uint8_t>(hash[position / 8]) >> (7 - position % 8)) & 1);
        }
        label[group] = alphabet[value];
    }
    return label;
}

std::string binary_hash(const std::string& label) {
    static const std::string alphabet = "0123456789abcdefghijklmnopqrstuv";
    require(label.size() == 32, "NSEC3 encoded next label length mismatch");
    std::string hash(20, '\0');
    for (size_t group = 0; group < label.size(); ++group) {
        size_t value = alphabet.find(label[group]);
        require(value != std::string::npos, "invalid NSEC3 next label alphabet");
        for (unsigned bit = 0; bit < 5; ++bit) {
            size_t position = group * 5 + bit;
            uint8_t byte = static_cast<uint8_t>(hash[position / 8]);
            byte |= ((value >> (4 - bit)) & 1) << (7 - position % 8);
            hash[position / 8] = static_cast<char>(byte);
        }
    }
    return hash;
}

std::string encode_nsec3_next(const std::string& rdata, uint32_t flags) {
    size_t hash_start = 0;
    if (!nsec3_next_position(rdata, hash_start)) return std::string(1, '\0') + rdata;
    std::string label = base32hex_hash(rdata.data() + hash_start);
    std::string name(1, static_cast<char>(label.size()));
    name += label;
    name.push_back('\0');
    std::string key = make_key(name, std::string(1, '\0'), flags);
    std::string stored(1, '\1');
    stored.append(rdata.data(), hash_start);
    stored += key;
    stored.append(rdata.data() + hash_start + 20, rdata.size() - hash_start - 20);
    return stored;
}

std::string decode_nsec3_next(const std::string& stored, uint32_t flags) {
    require(!stored.empty(), "missing NSEC3 next encoding mode");
    if (stored[0] == 0) return stored.substr(1);
    require(stored[0] == 1, "invalid NSEC3 next encoding mode");
    std::string payload = stored.substr(1);
    size_t hash_start = 0;
    require(nsec3_next_position(payload, hash_start), "invalid NSEC3 next-key prefix");
    size_t key_length = flags & kCompactKeyFlag ? 33 : 65;
    require(key_length <= payload.size() - hash_start, "truncated NSEC3 next key");
    std::string name = owner_from_key(payload.substr(hash_start, key_length), std::string(1, '\0'), flags);
    require(name.size() == 34 && static_cast<uint8_t>(name[0]) == 32 && name.back() == 0,
            "NSEC3 next key must contain exactly one label");
    std::string rdata = payload.substr(0, hash_start);
    rdata += binary_hash(name.substr(1, 32));
    rdata.append(payload.data() + hash_start + key_length, payload.size() - hash_start - key_length);
    return rdata;
}

size_t stored_rdata_size(const Record& record, uint32_t flags) {
    if (!(flags & kNsec3NextKeyFlag) || record.type != 50) return record.rdata.size();
    size_t hash_start = 0;
    if (!nsec3_next_position(record.rdata, hash_start)) return record.rdata.size() + 1;
    return record.rdata.size() + 1 + (flags & kCompactKeyFlag ? 33 : 65) - 20;
}

std::string canonical_wire(ldns_rr* rr) {
    ldns_rr2canonical(rr);
    uint8_t* wire = nullptr;
    size_t length = 0;
    ldns_status status = ldns_rr2wire(&wire, rr, LDNS_SECTION_ANSWER, &length);
    require(status == LDNS_STATUS_OK, std::string("RR serialization failed: ") + ldns_get_errorstr_by_id(status));
    require(length <= kMaxWire, "RR exceeds protocol bound");
    std::string result(reinterpret_cast<char*>(wire), length);
    std::free(wire);
    return result;
}

std::string recanonicalize_wire(const std::string& wire) {
    size_t position = 0;
    ldns_rr* rr = nullptr;
    ldns_status status = ldns_wire2rr(&rr, reinterpret_cast<const uint8_t*>(wire.data()), wire.size(),
                                    &position, LDNS_SECTION_ANSWER);
    require(status == LDNS_STATUS_OK && rr != nullptr && position == wire.size(), "invalid input wire RR");
    std::string result = canonical_wire(rr);
    ldns_rr_free(rr);
    return result;
}

void read_zone(const std::string& path, const std::string& origin_text,
               const std::function<void(const std::string&)>& consume) {
    FILE* input = std::fopen(path.c_str(), "rb");
    syscheck(input != nullptr, "open source");
    std::setvbuf(input, nullptr, _IOFBF, 65536);
    ldns_rdf* origin = ldns_dname_new_frm_str(origin_text.c_str());
    ldns_rdf* previous = nullptr;
    require(origin != nullptr, "invalid origin");
    uint32_t default_ttl = 3600;
    int line_number = 0;
    try {
        while (true) {
            ldns_rr* rr = nullptr;
            ldns_status status = ldns_rr_new_frm_fp_l(&rr, input, &default_ttl, &origin, &previous, &line_number);
            if (status == LDNS_STATUS_SYNTAX_TTL || status == LDNS_STATUS_SYNTAX_ORIGIN ||
                status == LDNS_STATUS_SYNTAX_EMPTY) {
                if (rr) ldns_rr_free(rr);
                if (std::feof(input)) break;
                continue;
            }
            if (status != LDNS_STATUS_OK) {
                if (rr) ldns_rr_free(rr);
                throw std::runtime_error("source parse line " + std::to_string(line_number) + ": " +
                                         ldns_get_errorstr_by_id(status));
            }
            if (rr) {
                std::string wire = canonical_wire(rr);
                ldns_rr_free(rr);
                consume(wire);
            } else if (std::feof(input)) break;
        }
    } catch (...) {
        std::fclose(input);
        ldns_rdf_deep_free(origin);
        ldns_rdf_deep_free(previous);
        throw;
    }
    require(!std::ferror(input), "source read failed");
    std::fclose(input);
    ldns_rdf_deep_free(origin);
    ldns_rdf_deep_free(previous);
}

void read_hex_lines(const std::string& path, const std::function<void(const std::string&)>& consume) {
    FILE* input = std::fopen(path.c_str(), "rb");
    syscheck(input != nullptr, "open hex stream");
    std::vector<char> line(2 * kMaxWire + 4);
    try {
        while (std::fgets(line.data(), line.size(), input)) {
            size_t length = std::strlen(line.data());
            require(length && line[length - 1] == '\n', "wire hex line exceeds bound or lacks newline");
            --length;
            if (length && line[length - 1] == '\r') --length;
            if (!length) continue;
            consume(recanonicalize_wire(unhex(line.data(), length)));
        }
        require(!std::ferror(input), "hex input read error");
    } catch (...) {
        std::fclose(input);
        throw;
    }
    std::fclose(input);
}

void write_all(FILE* file, const void* data, size_t size) {
    syscheck(std::fwrite(data, 1, size, file) == size, "write output");
}

void sync_directory(const fs::path& directory) {
    fs::path actual = directory.empty() ? fs::path(".") : directory;
    int descriptor = ::open(actual.c_str(), O_RDONLY | O_DIRECTORY);
    syscheck(descriptor >= 0, "open directory for sync");
    int result = ::fsync(descriptor);
    int saved_errno = errno;
    ::close(descriptor);
    errno = saved_errno;
    syscheck(result == 0, "fsync directory");
}

std::string index_key(const PageIndex& entry) {
    return std::string(reinterpret_cast<const char*>(entry.first_key), entry.first_key_length);
}

Bytes encode_page(const std::vector<Record>& records, bool pool, bool front, uint32_t flags = 0) {
    Bytes entries;
    Bytes definitions;
    std::map<std::string, uint32_t> pool_ids;
    std::string previous;
    uint32_t pool_count = 0;
    for (const auto& record : records) {
        std::string transformed;
        const std::string* payload = &record.rdata;
        if ((flags & kNsec3NextKeyFlag) && record.type == 50) {
            transformed = encode_nsec3_next(record.rdata, flags);
            payload = &transformed;
        }
        size_t common = 0;
        if (front) while (common < previous.size() && common < record.key.size() &&
                         previous[common] == record.key[common]) ++common;
        put_varint(entries, common);
        put_varint(entries, record.key.size() - common);
        entries.insert(entries.end(), record.key.begin() + common, record.key.end());
        put16(entries, record.type);
        put16(entries, record.klass);
        put32(entries, record.ttl);
        put_varint(entries, record.multiplicity);
        if (pool) {
            std::string typed;
            typed.push_back(record.type & 255);
            typed.push_back(record.type >> 8);
            typed.push_back(record.klass & 255);
            typed.push_back(record.klass >> 8);
            typed += *payload;
            auto found = pool_ids.find(typed);
            uint32_t id;
            if (found == pool_ids.end()) {
                id = pool_count++;
                pool_ids.emplace(std::move(typed), id);
                put_varint(definitions, payload->size());
                definitions.insert(definitions.end(), payload->begin(), payload->end());
            } else id = found->second;
            put_varint(entries, id);
        } else {
            put_varint(entries, payload->size());
            entries.insert(entries.end(), payload->begin(), payload->end());
        }
        previous = record.key;
    }
    Bytes raw;
    put32(raw, records.size());
    put32(raw, pool_count);
    put32(raw, entries.size());
    raw.insert(raw.end(), entries.begin(), entries.end());
    raw.insert(raw.end(), definitions.begin(), definitions.end());
    require(raw.size() <= kMaxPage, "decoded page exceeds bound");
    return raw;
}

std::vector<Record> decode_page(const Bytes& raw, bool pool, bool front, uint32_t flags = 0) {
    size_t position = 0;
    uint32_t count = get32(raw.data(), raw.size(), position);
    uint32_t pool_count = get32(raw.data(), raw.size(), position);
    uint32_t entries_length = get32(raw.data(), raw.size(), position);
    require(count <= raw.size() && pool_count <= raw.size(), "invalid page counts");
    require(entries_length <= raw.size() - position, "invalid page entry length");
    size_t entries_end = position + entries_length;
    std::vector<std::string> definitions;
    if (pool) {
        size_t definition_position = entries_end;
        definitions.reserve(pool_count);
        for (uint32_t i = 0; i < pool_count; ++i) {
            uint64_t length = get_varint(raw.data(), raw.size(), definition_position);
            require(length <= raw.size() - definition_position, "truncated pool entry");
            definitions.emplace_back(reinterpret_cast<const char*>(raw.data() + definition_position), length);
            definition_position += length;
        }
        require(definition_position == raw.size(), "trailing pool bytes");
    } else require(pool_count == 0 && entries_end == raw.size(), "invalid plain page layout");
    std::vector<Record> records;
    records.reserve(count);
    std::string previous;
    for (uint32_t i = 0; i < count; ++i) {
        Record record;
        uint64_t common = get_varint(raw.data(), entries_end, position);
        uint64_t suffix = get_varint(raw.data(), entries_end, position);
        require(common <= previous.size() && common + suffix <= kMaxKey && suffix <= entries_end - position,
                "invalid key front code");
        require(front || common == 0, "front code in disabled page");
        record.key = previous.substr(0, common);
        record.key.append(reinterpret_cast<const char*>(raw.data() + position), suffix);
        position += suffix;
        record.type = get16(raw.data(), entries_end, position);
        record.klass = get16(raw.data(), entries_end, position);
        record.ttl = get32(raw.data(), entries_end, position);
        record.multiplicity = get_varint(raw.data(), entries_end, position);
        require(record.multiplicity > 0, "zero RR multiplicity");
        uint64_t value = get_varint(raw.data(), entries_end, position);
        if (pool) {
            require(value < definitions.size(), "pool reference out of range");
            record.rdata = definitions[value];
        } else {
            require(value <= entries_end - position && value <= 65535 + 46, "truncated RDATA");
            record.rdata.assign(reinterpret_cast<const char*>(raw.data() + position), value);
            position += value;
        }
        if ((flags & kNsec3NextKeyFlag) && record.type == 50) record.rdata = decode_nsec3_next(record.rdata, flags);
        require(record.rdata.size() <= 65535, "decoded RDATA exceeds protocol bound");
        require(i == 0 || !byte_less(record.key, previous), "unsorted page keys");
        previous = record.key;
        records.push_back(std::move(record));
    }
    require(position == entries_end, "trailing record bytes");
    return records;
}

struct Options {
    std::string command;
    std::map<std::string, std::string> values;
    std::string get(const std::string& name, const std::string& fallback = "") const {
        auto found = values.find(name);
        return found == values.end() ? fallback : found->second;
    }
    std::string need(const std::string& name) const {
        auto result = get(name);
        require(!result.empty(), "missing --" + name);
        return result;
    }
};

Options parse_options(int argc, char** argv) {
    require(argc >= 2, "usage: native_zone build|canonical|dump|wire|query [options]");
    Options options;
    options.command = argv[1];
    for (int i = 2; i < argc; i += 2) {
        std::string option(argv[i]);
        require(option.rfind("--", 0) == 0 && i + 1 < argc, "options require --name value");
        require(options.values.emplace(option.substr(2), argv[i + 1]).second, "duplicate option " + option);
    }
    return options;
}

void stage(const std::string& name, double elapsed, const std::string& fields = "") {
    std::cerr << "STAGE {\"stage\":" << json_string(name) << ",\"seconds\":" << elapsed;
    if (!fields.empty()) std::cerr << ',' << fields;
    std::cerr << "}\n";
}

void run_sort(const fs::path& input, const fs::path& output, const fs::path& work,
              unsigned arena_mib, unsigned fan_in) {
    std::string buffer = std::to_string(arena_mib) + "M";
    std::string batch = "--batch-size=" + std::to_string(fan_in);
    pid_t child = ::fork();
    syscheck(child >= 0, "fork sort");
    if (child == 0) {
        ::setenv("LC_ALL", "C", 1);
        ::execlp("sort", "sort", "--parallel=1", batch.c_str(), "-S", buffer.c_str(),
                 "-T", work.c_str(), "-o", output.c_str(), input.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    syscheck(::waitpid(child, &status, 0) == child, "wait sort");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "external sort failed");
}

struct SortFrame {
    std::string key;
    std::string wire;
};

bool frame_less(const SortFrame& left, const SortFrame& right) {
    if (left.key != right.key) return byte_less(left.key, right.key);
    return byte_less(left.wire, right.wire);
}

void write_sort_frame(FILE* output, const std::string& key, const std::string& wire) {
    require(key.size() <= kMaxKey && wire.size() <= kMaxWire + 1, "run record exceeds protocol bound");
    uint8_t header[6] = {static_cast<uint8_t>(key.size()), static_cast<uint8_t>(key.size() >> 8),
                         static_cast<uint8_t>(wire.size()), static_cast<uint8_t>(wire.size() >> 8),
                         static_cast<uint8_t>(wire.size() >> 16), static_cast<uint8_t>(wire.size() >> 24)};
    write_all(output, header, sizeof(header));
    write_all(output, key.data(), key.size());
    write_all(output, wire.data(), wire.size());
}

bool read_sort_frame(FILE* input, SortFrame& frame) {
    uint8_t header[6];
    size_t got = std::fread(header, 1, sizeof(header), input);
    if (got == 0) {
        require(!std::ferror(input), "binary run read error");
        return false;
    }
    require(got == sizeof(header), "truncated binary run header");
    size_t position = 0;
    uint16_t key_size = get16(header, sizeof(header), position);
    uint32_t wire_size = get32(header, sizeof(header), position);
    require(key_size <= kMaxKey && wire_size <= kMaxWire + 1, "invalid binary run record length");
    frame.key.resize(key_size);
    frame.wire.resize(wire_size);
    require(std::fread(frame.key.data(), 1, key_size, input) == key_size &&
            std::fread(frame.wire.data(), 1, wire_size, input) == wire_size, "truncated binary run record");
    return true;
}

class NativeRunSorter {
public:
    NativeRunSorter(fs::path work, unsigned arena_mib, unsigned fan_in)
        : work_(std::move(work)), fan_in_(fan_in) {
        size_t budget = static_cast<size_t>(arena_mib) << 20;
        max_items_ = (budget / 4) / sizeof(Item);
        size_t index_bytes = max_items_ * sizeof(Item);
        arena_.resize(budget - index_bytes);
        items_.reserve(max_items_);
    }

    void add(const std::string& key, const std::string& wire) {
        size_t bytes = key.size() + wire.size();
        require(bytes <= arena_.size(), "single run record exceeds configured arena");
        if (items_.size() == max_items_ || bytes > arena_.size() - used_) flush();
        Item item{};
        item.offset = used_;
        item.key_length = key.size();
        item.wire_length = wire.size();
        std::memcpy(arena_.data() + used_, key.data(), key.size());
        used_ += key.size();
        std::memcpy(arena_.data() + used_, wire.data(), wire.size());
        used_ += wire.size();
        items_.push_back(item);
    }

    void finish_runs() { flush(); }

    void prepare_merges() {
        while (run_count_ > fan_in_) {
            uint64_t output_count = 0;
            for (uint64_t start = 0; start < run_count_; start += fan_in_) {
                uint64_t count = std::min<uint64_t>(fan_in_, run_count_ - start);
                fs::path output_path = path(pass_ + 1, output_count);
                FILE* output = std::fopen(output_path.c_str(), "wb");
                syscheck(output != nullptr, "open merged binary run");
                merge_group(pass_, start, count, [&](const SortFrame& frame) {
                    write_sort_frame(output, frame.key, frame.wire);
                });
                syscheck(std::fclose(output) == 0, "close merged binary run");
                for (uint64_t i = 0; i < count; ++i) fs::remove(path(pass_, start + i));
                ++output_count;
            }
            ++pass_;
            run_count_ = output_count;
            ++intermediate_passes_;
        }
    }

    void final_merge(const std::function<void(const SortFrame&)>& consume) {
        if (run_count_) merge_group(pass_, 0, run_count_, consume);
    }

    bool finish_owner(const std::function<void(const SortFrame&)>& consume) {
        bool spilled = run_count_ != 0;
        if (spilled) {
            finish_runs();
            prepare_merges();
            final_merge(consume);
            for (uint64_t i = 0; i < run_count_; ++i) fs::remove(path(pass_, i));
            run_count_ = 0;
            pass_ = 0;
        } else {
            auto start = Clock::now();
            sort_items();
            memory_sort_seconds_ += seconds_since(start);
            SortFrame frame;
            for (const auto& item : items_) {
                const char* data = reinterpret_cast<const char*>(arena_.data() + item.offset);
                frame.key.assign(data, item.key_length);
                frame.wire.assign(data + item.key_length, item.wire_length);
                consume(frame);
            }
            used_ = 0;
            items_.clear();
        }
        return spilled;
    }

    double run_sort_write_seconds() const { return run_sort_write_seconds_; }
    uint64_t initial_runs() const { return initial_runs_; }
    uint64_t intermediate_passes() const { return intermediate_passes_; }
    size_t arena_bytes() const { return arena_.size(); }
    size_t index_bytes() const { return max_items_ * sizeof(Item); }
    double memory_sort_seconds() const { return memory_sort_seconds_; }

private:
    struct Item {
        uint32_t offset;
        uint32_t wire_length;
        uint16_t key_length;
        uint16_t reserved;
    };

    struct Cursor {
        FILE* input = nullptr;
        SortFrame frame;
    };

    fs::path path(uint64_t pass, uint64_t number) const {
        return work_ / ("binary_run_" + std::to_string(pass) + "_" + std::to_string(number) + ".bin");
    }

    bool item_less(const Item& left, const Item& right) const {
        const uint8_t* lk = arena_.data() + left.offset;
        const uint8_t* rk = arena_.data() + right.offset;
        size_t key_common = std::min(left.key_length, right.key_length);
        int comparison = key_common ? std::memcmp(lk, rk, key_common) : 0;
        if (comparison) return comparison < 0;
        if (left.key_length != right.key_length) return left.key_length < right.key_length;
        size_t common = std::min(left.wire_length, right.wire_length);
        comparison = common ? std::memcmp(lk + left.key_length, rk + right.key_length, common) : 0;
        return comparison < 0 || (comparison == 0 && left.wire_length < right.wire_length);
    }

    void sort_items() {
        std::sort(items_.begin(), items_.end(), [&](const Item& left, const Item& right) {
            return item_less(left, right);
        });
    }

    void flush() {
        if (items_.empty()) return;
        auto start = Clock::now();
        sort_items();
        FILE* output = std::fopen(path(0, run_count_).c_str(), "wb");
        syscheck(output != nullptr, "open native binary run");
        std::setvbuf(output, nullptr, _IOFBF, 65536);
        for (const auto& item : items_) {
            const uint8_t* data = arena_.data() + item.offset;
            uint8_t header[6] = {static_cast<uint8_t>(item.key_length), static_cast<uint8_t>(item.key_length >> 8),
                                 static_cast<uint8_t>(item.wire_length), static_cast<uint8_t>(item.wire_length >> 8),
                                 static_cast<uint8_t>(item.wire_length >> 16), static_cast<uint8_t>(item.wire_length >> 24)};
            write_all(output, header, sizeof(header));
            write_all(output, data, static_cast<size_t>(item.key_length) + item.wire_length);
        }
        syscheck(std::fclose(output) == 0, "close native binary run");
        ++run_count_;
        ++initial_runs_;
        used_ = 0;
        items_.clear();
        run_sort_write_seconds_ += seconds_since(start);
    }

    void merge_group(uint64_t pass, uint64_t first, uint64_t count,
                     const std::function<void(const SortFrame&)>& consume) {
        require(count <= fan_in_, "merge fan-in exceeds configured bound");
        std::vector<Cursor> cursors(count);
        std::vector<size_t> heap;
        heap.reserve(count);
        auto later = [&](size_t left, size_t right) {
            return frame_less(cursors[right].frame, cursors[left].frame);
        };
        try {
            for (size_t i = 0; i < count; ++i) {
                cursors[i].input = std::fopen(path(pass, first + i).c_str(), "rb");
                syscheck(cursors[i].input != nullptr, "open binary merge input");
                std::setvbuf(cursors[i].input, nullptr, _IOFBF, 65536);
                if (read_sort_frame(cursors[i].input, cursors[i].frame)) {
                    heap.push_back(i);
                    std::push_heap(heap.begin(), heap.end(), later);
                }
            }
            while (!heap.empty()) {
                std::pop_heap(heap.begin(), heap.end(), later);
                size_t index = heap.back();
                heap.pop_back();
                consume(cursors[index].frame);
                if (read_sort_frame(cursors[index].input, cursors[index].frame)) {
                    heap.push_back(index);
                    std::push_heap(heap.begin(), heap.end(), later);
                }
            }
        } catch (...) {
            for (auto& cursor : cursors) if (cursor.input) std::fclose(cursor.input);
            throw;
        }
        for (auto& cursor : cursors) if (cursor.input) std::fclose(cursor.input);
    }

    fs::path work_;
    unsigned fan_in_;
    Bytes arena_;
    std::vector<Item> items_;
    size_t max_items_ = 0;
    size_t used_ = 0;
    uint64_t pass_ = 0;
    uint64_t run_count_ = 0;
    uint64_t initial_runs_ = 0;
    uint64_t intermediate_passes_ = 0;
    double run_sort_write_seconds_ = 0;
    double memory_sort_seconds_ = 0;
};

PageIndex write_page_extent(FILE* output, const std::vector<Record>& records, uint32_t flags, unsigned codec) {
    require(!records.empty(), "cannot store an empty page");
    Bytes raw = encode_page(records, flags & kPoolFlag, flags & kFrontFlag, flags);
    Bytes compressed;
    unsigned actual_codec = 0;
    if (codec == 1) {
        compressed.resize(LZ4_compressBound(raw.size()));
        int result = LZ4_compress_default(reinterpret_cast<const char*>(raw.data()),
                                          reinterpret_cast<char*>(compressed.data()), raw.size(), compressed.size());
        require(result > 0, "LZ4 encoding failed");
        compressed.resize(result);
    } else if (codec == 2) {
        compressed.resize(ZSTD_compressBound(raw.size()));
        size_t result = ZSTD_compress(compressed.data(), compressed.size(), raw.data(), raw.size(), 3);
        require(!ZSTD_isError(result), "Zstd encoding failed");
        compressed.resize(result);
    }
    if (codec && compressed.size() < raw.size()) actual_codec = codec;
    const Bytes& stored = actual_codec ? compressed : raw;
    PageIndex entry{};
    off_t offset = ::ftello(output);
    syscheck(offset >= 0, "page output offset");
    entry.offset = offset;
    entry.encoded_size = stored.size();
    entry.decoded_size = raw.size();
    entry.record_count = records.size();
    entry.first_key_length = records.front().key.size();
    entry.codec = actual_codec;
    entry.checksum = checksum(raw.data(), raw.size());
    std::memcpy(entry.first_key, records.front().key.data(), entry.first_key_length);
    write_all(output, stored.data(), stored.size());
    return entry;
}

uint64_t append_final_index(FILE* output, const fs::path& fixed_path, ImageHeader& header) {
    require(header.page_count <= std::numeric_limits<uint64_t>::max() / sizeof(PageIndex) &&
            fs::file_size(fixed_path) == header.page_count * sizeof(PageIndex), "fixed staging index count mismatch");
    FILE* input = std::fopen(fixed_path.c_str(), "rb");
    syscheck(input != nullptr, "read fixed staging index");
    if (!(header.flags & kPackedIndexFlag)) {
        std::array<uint8_t, 65536> transfer{};
        while (size_t got = std::fread(transfer.data(), 1, transfer.size(), input))
            write_all(output, transfer.data(), got);
        require(!std::ferror(input), "fixed staging index read failed");
        std::fclose(input);
        std::memset(header.reserved, 0, sizeof(PackedIndexMeta));
        return header.page_count * sizeof(PageIndex);
    }
    fs::path restart_path = fixed_path;
    restart_path += ".packed_restarts";
    FILE* restarts = std::fopen(restart_path.c_str(), "wb");
    syscheck(restarts != nullptr, "open packed restart output");
    PackedIndexMeta meta{};
    std::memcpy(meta.magic, "ZIMIDX1\0", 8);
    meta.restart_interval = kIndexRestartInterval;
    meta.restart_entry_size = sizeof(IndexRestart);
    meta.restart_checksum = checksum(nullptr, 0);
    Bytes group;
    std::string previous;
    for (uint64_t number = 0; number < header.page_count; ++number) {
        PageIndex entry{};
        require(std::fread(&entry, sizeof(entry), 1, input) == 1 && entry.first_key_length <= kMaxKey,
                "truncated fixed staging directory");
        if (number % kIndexRestartInterval == 0) {
            previous.clear();
            group.clear();
        }
        std::string key = index_key(entry);
        size_t common = 0;
        if ((header.flags & kFrontFlag) && number % kIndexRestartInterval != 0)
            while (common < previous.size() && common < key.size() && previous[common] == key[common]) ++common;
        put_varint(group, common);
        put_varint(group, key.size() - common);
        group.insert(group.end(), key.begin() + common, key.end());
        put64(group, entry.offset);
        put32(group, entry.encoded_size);
        put32(group, entry.decoded_size);
        put32(group, entry.record_count);
        put16(group, entry.codec);
        put64(group, entry.checksum);
        previous = std::move(key);
        if ((number + 1) % kIndexRestartInterval == 0 || number + 1 == header.page_count) {
            IndexRestart restart{meta.data_bytes, checksum(group.data(), group.size())};
            write_all(restarts, &restart, sizeof(restart));
            meta.restart_checksum = checksum_continue(meta.restart_checksum,
                reinterpret_cast<const uint8_t*>(&restart), sizeof(restart));
            write_all(output, group.data(), group.size());
            meta.data_bytes += group.size();
            ++meta.restart_count;
        }
    }
    std::fclose(input);
    syscheck(std::fclose(restarts) == 0, "close packed restart output");
    meta.restart_offset = meta.data_bytes;
    FILE* restart_input = std::fopen(restart_path.c_str(), "rb");
    syscheck(restart_input != nullptr, "read packed restarts");
    std::array<uint8_t, 65536> transfer{};
    while (size_t got = std::fread(transfer.data(), 1, transfer.size(), restart_input))
        write_all(output, transfer.data(), got);
    require(!std::ferror(restart_input), "packed restart read failed");
    std::fclose(restart_input);
    std::memcpy(header.reserved, &meta, sizeof(meta));
    return meta.data_bytes + meta.restart_count * sizeof(IndexRestart);
}

fs::path resolve_snapshot_path(fs::path path, bool require_initial_pointer = false) {
    path = fs::absolute(path).lexically_normal();
    for (unsigned hop = 0; hop < 8; ++hop) {
        std::ifstream input(path, std::ios::binary);
        require(input.good(), "cannot open image or CURRENT " + path.string());
        std::array<char, 8> magic{};
        input.read(magic.data(), magic.size());
        if (input.gcount() == static_cast<std::streamsize>(magic.size()) &&
            (std::memcmp(magic.data(), "ZIMDNS1\0", 8) == 0 ||
             std::memcmp(magic.data(), "ZIMGEN1\0", 8) == 0)) {
            require(!require_initial_pointer || hop != 0, "CURRENT replacement target must be a text pointer");
            return path;
        }
        require(fs::file_size(path) > 0 && fs::file_size(path) <= 4097, "unsupported image or CURRENT format");
        input.clear();
        input.seekg(0);
        std::string relative;
        require(static_cast<bool>(std::getline(input, relative)) && !relative.empty() && relative.size() <= 4096 &&
                relative.find('\0') == std::string::npos, "invalid CURRENT path");
        std::string extra;
        require(!std::getline(input, extra), "CURRENT must contain a single path");
        path = (path.parent_path() / relative).lexically_normal();
    }
    throw std::runtime_error("CURRENT pointer chain exceeds bound");
}

constexpr uint32_t kCowNodeMagic = 0x314e495a;
constexpr size_t kMaxCowNode = 1024;

struct CowNode {
    bool leaf = false;
    PageIndex page{};
    CowRef left{};
    CowRef right{};
};

struct CowCheck {
    uint64_t nodes = 0;
    uint64_t leaves = 0;
    uint64_t bytes = 0;
    uint32_t maximum_height = 0;
    uint32_t maximum_balance = 0;
};

void validate_cow_ref(const CowRef& ref) {
    require(ref.pages > 0 && ref.height > 0 && ref.height <= 64 && ref.offset >= sizeof(ImageHeader) &&
            ref.length >= 39 && ref.length <= kMaxCowNode, "invalid persistent node reference");
}

CowNode decode_cow_node(const uint8_t* bytes, size_t length, const CowRef& ref) {
    validate_cow_ref(ref);
    require(length == ref.length && checksum(bytes, length) == ref.checksum, "persistent node checksum mismatch");
    size_t position = 0;
    require(get32(bytes, length, position) == kCowNodeMagic && length - position >= 4, "invalid persistent node magic");
    unsigned kind = bytes[position++];
    require(kind <= 1 && bytes[position++] == 1 && get16(bytes, length, position) == 0,
            "unsupported persistent node encoding");
    CowNode node;
    node.leaf = kind == 0;
    if (node.leaf) {
        uint64_t key_length = get_varint(bytes, length, position);
        require(key_length <= kMaxKey && key_length <= length - position, "invalid persistent leaf key");
        node.page.first_key_length = key_length;
        std::memcpy(node.page.first_key, bytes + position, key_length);
        position += key_length;
        node.page.offset = get64(bytes, length, position);
        node.page.encoded_size = get32(bytes, length, position);
        node.page.decoded_size = get32(bytes, length, position);
        node.page.record_count = get32(bytes, length, position);
        node.page.codec = get16(bytes, length, position);
        node.page.checksum = get64(bytes, length, position);
        require(ref.pages == 1 && ref.height == 1, "persistent leaf rank metadata mismatch");
    } else {
        require(length - position >= 2 * sizeof(CowRef), "truncated persistent children");
        std::memcpy(&node.left, bytes + position, sizeof(CowRef));
        position += sizeof(CowRef);
        std::memcpy(&node.right, bytes + position, sizeof(CowRef));
        position += sizeof(CowRef);
        validate_cow_ref(node.left);
        validate_cow_ref(node.right);
        require(node.left.pages <= std::numeric_limits<uint64_t>::max() - node.right.pages &&
                ref.pages == node.left.pages + node.right.pages &&
                ref.height == 1 + std::max(node.left.height, node.right.height) &&
                std::abs(static_cast<int>(node.left.height) - static_cast<int>(node.right.height)) <= 1,
                "persistent branch rank or balance mismatch");
    }
    require(position == length, "trailing persistent node bytes");
    return node;
}

Bytes encode_cow_node(const CowNode& node) {
    Bytes bytes;
    put32(bytes, kCowNodeMagic);
    bytes.push_back(node.leaf ? 0 : 1);
    bytes.push_back(1);
    put16(bytes, 0);
    if (node.leaf) {
        put_varint(bytes, node.page.first_key_length);
        bytes.insert(bytes.end(), node.page.first_key, node.page.first_key + node.page.first_key_length);
        put64(bytes, node.page.offset);
        put32(bytes, node.page.encoded_size);
        put32(bytes, node.page.decoded_size);
        put32(bytes, node.page.record_count);
        put16(bytes, node.page.codec);
        put64(bytes, node.page.checksum);
    } else {
        const auto* left = reinterpret_cast<const uint8_t*>(&node.left);
        const auto* right = reinterpret_cast<const uint8_t*>(&node.right);
        bytes.insert(bytes.end(), left, left + sizeof(CowRef));
        bytes.insert(bytes.end(), right, right + sizeof(CowRef));
    }
    require(bytes.size() <= kMaxCowNode, "persistent node exceeds bound");
    return bytes;
}

class Image {
public:
    explicit Image(const std::string& path) {
        snapshot_path_ = resolve_snapshot_path(path);
        data_path_ = snapshot_path_;
        fd_ = ::open(data_path_.c_str(), O_RDONLY);
        syscheck(fd_ >= 0, "open image");
        struct stat statbuf{};
        syscheck(::fstat(fd_, &statbuf) == 0, "stat image");
        require(statbuf.st_size >= static_cast<off_t>(sizeof(ImageHeader)), "truncated image header");
        std::array<uint8_t, 8> magic{};
        syscheck(::pread(fd_, magic.data(), magic.size(), 0) == static_cast<ssize_t>(magic.size()), "read image magic");
        bool generation = std::memcmp(magic.data(), "ZIMGEN1\0", 8) == 0;
        if (generation) {
            GenerationHeader descriptor{};
            syscheck(::pread(fd_, &descriptor, sizeof(descriptor), 0) == static_cast<ssize_t>(sizeof(descriptor)),
                     "read generation descriptor");
            require(descriptor.version == 1 && descriptor.path_length > 0 && descriptor.path_length <= 4096 &&
                    static_cast<uint64_t>(statbuf.st_size) == sizeof(descriptor) + descriptor.path_length + sizeof(uint64_t),
                    "invalid generation descriptor");
            std::string relative_path(descriptor.path_length, '\0');
            syscheck(::pread(fd_, relative_path.data(), relative_path.size(), sizeof(descriptor)) ==
                     static_cast<ssize_t>(relative_path.size()), "read generation data path");
            uint64_t saved_checksum = 0;
            syscheck(::pread(fd_, &saved_checksum, sizeof(saved_checksum), sizeof(descriptor) + relative_path.size()) ==
                     static_cast<ssize_t>(sizeof(saved_checksum)), "read generation checksum");
            Bytes check_bytes(sizeof(descriptor) + relative_path.size());
            std::memcpy(check_bytes.data(), &descriptor, sizeof(descriptor));
            std::memcpy(check_bytes.data() + sizeof(descriptor), relative_path.data(), relative_path.size());
            require(checksum(check_bytes.data(), check_bytes.size()) == saved_checksum &&
                    relative_path.find('\0') == std::string::npos, "generation checksum mismatch");
            header_ = descriptor.snapshot;
            ::close(fd_);
            data_path_ = (data_path_.parent_path() / relative_path).lexically_normal();
            fd_ = ::open(data_path_.c_str(), O_RDONLY);
            syscheck(fd_ >= 0, "open generation data file");
            syscheck(::fstat(fd_, &statbuf) == 0, "stat generation data file");
        }
        size_ = statbuf.st_size;
        require(size_ >= sizeof(ImageHeader), "truncated generation data file");
        void* mapped = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
        syscheck(mapped != MAP_FAILED, "mmap image");
        data_ = static_cast<const uint8_t*>(mapped);
        if (!generation) std::memcpy(&header_, data_, sizeof(header_));
        require(std::memcmp(header_.magic, "ZIMDNS1\0", 8) == 0 && header_.version == kVersion,
                "unsupported image format");
        require(header_.header_size == sizeof(ImageHeader) && header_.origin_length > 0 &&
                header_.origin_length <= 255 && !(header_.flags & ~(kPoolFlag | kFrontFlag | kPackedIndexFlag | kCowIndexFlag | kCompactKeyFlag | kNsec3NextKeyFlag)) &&
                !((header_.flags & kPackedIndexFlag) && (header_.flags & kCowIndexFlag)),
                "invalid image header");
        require(header_.index_offset >= sizeof(ImageHeader) && header_.index_offset <= size_ &&
                final_index_bytes(header_) <= size_ - header_.index_offset, "invalid index range");
        if (header_.flags & kPackedIndexFlag) {
            std::memcpy(&packed_meta_, header_.reserved, sizeof(packed_meta_));
            require(packed_meta_.restart_count == (header_.page_count + kIndexRestartInterval - 1) / kIndexRestartInterval &&
                    header_.page_count <= packed_meta_.data_bytes / 32, "invalid packed index counts");
            const uint8_t* table = data_ + header_.index_offset + packed_meta_.restart_offset;
            require(checksum(table, packed_meta_.restart_count * sizeof(IndexRestart)) == packed_meta_.restart_checksum,
                    "packed restart table checksum mismatch");
        }
        if (header_.flags & kCowIndexFlag) {
            std::memcpy(&cow_meta_, header_.reserved, sizeof(cow_meta_));
            require(std::memcmp(cow_meta_.magic, "ZIMCOW1\0", 8) == 0 && cow_meta_.root.pages == header_.page_count,
                    "invalid persistent index metadata");
            if (header_.page_count) cow_node(cow_meta_.root);
            else require(cow_meta_.root.offset == 0 && cow_meta_.root.length == 0 && cow_meta_.root.height == 0 &&
                         cow_meta_.root.checksum == 0, "invalid empty persistent root");
        }
        origin_.assign(reinterpret_cast<const char*>(header_.origin), header_.origin_length);
        require(wire_name_length(header_.origin, header_.origin_length) == header_.origin_length,
                "invalid stored origin");
    }

    ~Image() {
        if (data_) ::munmap(const_cast<uint8_t*>(data_), size_);
        if (fd_ >= 0) ::close(fd_);
    }

    Image(const Image&) = delete;
    Image& operator=(const Image&) = delete;

    const std::string& origin() const { return origin_; }
    const ImageHeader& header() const { return header_; }
    const fs::path& data_path() const { return data_path_; }
    const fs::path& snapshot_path() const { return snapshot_path_; }
    CowRef cow_root() const { return cow_meta_.root; }
    const CowIndexMeta& cow_meta() const { return cow_meta_; }
    uint64_t committed_bytes() const { return header_.index_offset + final_index_bytes(header_); }

    CowNode cow_node(const CowRef& ref) const {
        validate_cow_ref(ref);
        require(ref.offset <= committed_bytes() && ref.length <= committed_bytes() - ref.offset,
                "persistent node lies outside committed snapshot");
        return decode_cow_node(data_ + ref.offset, ref.length, ref);
    }

    CowCheck check_cow_tree() const {
        require(header_.flags & kCowIndexFlag, "persistent tree check requires cow index");
        CowCheck result;
        std::string previous;
        bool first = true;
        std::function<void(const CowRef&)> visit = [&](const CowRef& ref) {
            if (!ref.pages) return;
            CowNode node = cow_node(ref);
            ++result.nodes;
            result.bytes += ref.length;
            result.maximum_height = std::max(result.maximum_height, ref.height);
            if (node.leaf) {
                validate_descriptor(node.page);
                std::string key = index_key(node.page);
                require(first || !byte_less(key, previous), "persistent leaf order mismatch");
                first = false;
                previous = std::move(key);
                ++result.leaves;
            } else {
                result.maximum_balance = std::max(result.maximum_balance,
                    static_cast<uint32_t>(std::abs(static_cast<int>(node.left.height) - static_cast<int>(node.right.height))));
                visit(node.left);
                visit(node.right);
            }
        };
        visit(cow_meta_.root);
        require(result.leaves == header_.page_count, "persistent leaf count mismatch");
        return result;
    }

    PageIndex index(size_t number) const {
        require(number < header_.page_count, "page index out of range");
        if (header_.flags & kCowIndexFlag) {
            CowRef ref = cow_meta_.root;
            uint64_t rank = number;
            for (unsigned step = 0; step < 64; ++step) {
                CowNode node = cow_node(ref);
                if (node.leaf) {
                    require(rank == 0, "persistent page rank out of range");
                    validate_descriptor(node.page);
                    return node.page;
                }
                if (rank < node.left.pages) ref = node.left;
                else { rank -= node.left.pages; ref = node.right; }
            }
            throw std::runtime_error("persistent index traversal exceeded height bound");
        }
        if (header_.flags & kPackedIndexFlag) {
            uint64_t group = number / kIndexRestartInterval;
            if (cached_index_group_ != group) load_index_group(group);
            return cached_index_[number % kIndexRestartInterval];
        }
        PageIndex entry{};
        std::memcpy(&entry, data_ + header_.index_offset + number * sizeof(PageIndex), sizeof(entry));
        validate_descriptor(entry);
        return entry;
    }

    std::vector<Record> page(size_t number) const {
        auto descriptor = index(number);
        const uint8_t* encoded = data_ + descriptor.offset;
        Bytes raw(descriptor.decoded_size);
        if (descriptor.codec == 0) {
            require(descriptor.encoded_size == descriptor.decoded_size, "invalid raw page length");
            std::memcpy(raw.data(), encoded, raw.size());
        } else if (descriptor.codec == 1) {
            int result = LZ4_decompress_safe(reinterpret_cast<const char*>(encoded),
                                             reinterpret_cast<char*>(raw.data()), descriptor.encoded_size, raw.size());
            require(result == static_cast<int>(raw.size()), "LZ4 page decode failure");
        } else {
            size_t result = ZSTD_decompress(raw.data(), raw.size(), encoded, descriptor.encoded_size);
            require(!ZSTD_isError(result) && result == raw.size(), "Zstd page decode failure");
        }
        require(checksum(raw.data(), raw.size()) == descriptor.checksum, "page checksum mismatch");
        auto records = decode_page(raw, header_.flags & kPoolFlag, header_.flags & kFrontFlag, header_.flags);
        require(records.size() == descriptor.record_count && !records.empty() &&
                records.front().key == index_key(descriptor), "page directory mismatch");
        return records;
    }

    void each(const std::function<void(const Record&)>& consume) const {
        for (size_t i = 0; i < header_.page_count; ++i)
            for (const auto& record : page(i)) consume(record);
    }

    size_t first_possible_page(const std::string& key) const {
        size_t lo = 0, hi = header_.page_count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (byte_less(index_key(index(mid)), key)) lo = mid + 1;
            else hi = mid;
        }
        return lo == 0 ? 0 : lo - 1;
    }

    std::vector<Record> get_rrset(const std::string& key, unsigned type = 0) const {
        std::vector<Record> found;
        size_t start = first_possible_page(key);
        for (size_t i = start; i < header_.page_count; ++i) {
            if (i > start && byte_less(key, index_key(index(i)))) break;
            for (const auto& record : page(i)) {
                if (byte_less(key, record.key)) return found;
                if (record.key == key && (type == 0 || record.type == type)) found.push_back(record);
            }
        }
        return found;
    }

    bool has_type(const std::string& key, unsigned type) const {
        size_t start = first_possible_page(key);
        for (size_t i = start; i < header_.page_count; ++i) {
            if (i > start && byte_less(key, index_key(index(i)))) return false;
            for (const auto& record : page(i)) {
                if (byte_less(key, record.key)) return false;
                if (record.key == key && (type == 0 || record.type == type)) return true;
            }
        }
        return false;
    }

    std::pair<std::string, std::string> lookup(const std::string& key) const {
        size_t start = first_possible_page(key);
        for (size_t i = start; i < header_.page_count; ++i)
            for (const auto& record : page(i)) {
                if (record.key == key) return {"exact", record.key};
                if (byte_less(key, record.key)) return {"successor", record.key};
            }
        return {"none", ""};
    }

    std::string name_state(const std::string& key) const {
        auto located = lookup(key);
        if (located.first == "exact") return "explicit";
        if (key.empty()) return "ent";
        if (located.first == "successor" && located.second.size() > key.size() &&
            std::memcmp(located.second.data(), key.data(), key.size()) == 0) return "ent";
        return "absent";
    }

private:
    void validate_descriptor(const PageIndex& entry) const {
        require(entry.first_key_length <= kMaxKey && entry.decoded_size >= 12 && entry.decoded_size <= kMaxPage &&
                entry.offset >= sizeof(ImageHeader) && entry.offset <= header_.index_offset &&
                entry.encoded_size <= header_.index_offset - entry.offset && entry.codec <= 2,
                "invalid page descriptor");
    }

    IndexRestart index_restart(uint64_t group) const {
        require(group < packed_meta_.restart_count, "packed restart out of range");
        IndexRestart restart{};
        std::memcpy(&restart, data_ + header_.index_offset + packed_meta_.restart_offset + group * sizeof(IndexRestart),
                    sizeof(restart));
        require(restart.offset < packed_meta_.data_bytes, "packed restart offset out of range");
        return restart;
    }

    void load_index_group(uint64_t group) const {
        IndexRestart restart = index_restart(group);
        uint64_t end = group + 1 < packed_meta_.restart_count ? index_restart(group + 1).offset : packed_meta_.data_bytes;
        require(end > restart.offset && end - restart.offset <= kIndexRestartInterval * (kMaxKey + 64),
                "packed index group length out of range");
        const uint8_t* bytes = data_ + header_.index_offset + restart.offset;
        size_t size = end - restart.offset;
        require(checksum(bytes, size) == restart.checksum, "packed index group checksum mismatch");
        uint64_t count = std::min<uint64_t>(kIndexRestartInterval, header_.page_count - group * kIndexRestartInterval);
        std::string previous;
        size_t position = 0;
        for (uint64_t i = 0; i < count; ++i) {
            uint64_t common = get_varint(bytes, size, position);
            uint64_t suffix = get_varint(bytes, size, position);
            require(common <= previous.size() && common + suffix <= kMaxKey && suffix <= size - position &&
                    (i != 0 || common == 0) && ((header_.flags & kFrontFlag) || common == 0),
                    "invalid packed directory front code");
            std::string key = previous.substr(0, common);
            key.append(reinterpret_cast<const char*>(bytes + position), suffix);
            position += suffix;
            require(i == 0 || !byte_less(key, previous), "unsorted packed index group");
            PageIndex entry{};
            entry.first_key_length = key.size();
            std::memcpy(entry.first_key, key.data(), key.size());
            entry.offset = get64(bytes, size, position);
            entry.encoded_size = get32(bytes, size, position);
            entry.decoded_size = get32(bytes, size, position);
            entry.record_count = get32(bytes, size, position);
            entry.codec = get16(bytes, size, position);
            entry.checksum = get64(bytes, size, position);
            validate_descriptor(entry);
            cached_index_[i] = entry;
            previous = std::move(key);
        }
        require(position == size, "trailing packed index group bytes");
        cached_index_group_ = group;
    }

    int fd_ = -1;
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    ImageHeader header_{};
    std::string origin_;
    fs::path data_path_;
    fs::path snapshot_path_;
    PackedIndexMeta packed_meta_{};
    CowIndexMeta cow_meta_{};
    mutable uint64_t cached_index_group_ = std::numeric_limits<uint64_t>::max();
    mutable std::array<PageIndex, kIndexRestartInterval> cached_index_{};
};

class CowStore {
public:
    CowStore(FILE* data, const Image* source = nullptr) : data_(data), source_(source) {}

    CowNode read(const CowRef& ref) {
        validate_cow_ref(ref);
        for (const auto& entry : cache_)
            if (entry.ref.offset == ref.offset && entry.ref.length == ref.length && entry.ref.checksum == ref.checksum &&
                entry.ref.pages == ref.pages && entry.ref.height == ref.height) return entry.node;
        CowNode node;
        if (source_ && (source_->header().flags & kCowIndexFlag) &&
            ref.offset <= source_->committed_bytes() && ref.length <= source_->committed_bytes() - ref.offset)
            node = source_->cow_node(ref);
        else {
            syscheck(std::fflush(data_) == 0, "flush persistent nodes before reading");
            std::array<uint8_t, kMaxCowNode> bytes{};
            syscheck(::pread(::fileno(data_), bytes.data(), ref.length, ref.offset) == static_cast<ssize_t>(ref.length),
                     "read new persistent node");
            node = decode_cow_node(bytes.data(), ref.length, ref);
        }
        cache_[next_cache_] = {ref, node};
        next_cache_ = (next_cache_ + 1) % cache_.size();
        return node;
    }

    CowRef leaf(const PageIndex& page) {
        CowNode node;
        node.leaf = true;
        node.page = page;
        return write(node, 1, 1);
    }

    CowRef join(const CowRef& left, const CowRef& right) {
        if (!left.pages) return right;
        if (!right.pages) return left;
        if (left.height > right.height + 1) {
            CowNode node = read(left);
            require(!node.leaf, "persistent join expected left branch");
            return balance(node.left, join(node.right, right));
        }
        if (right.height > left.height + 1) {
            CowNode node = read(right);
            require(!node.leaf, "persistent join expected right branch");
            return balance(join(left, node.left), node.right);
        }
        return branch(left, right);
    }

    std::pair<CowRef, CowRef> split(const CowRef& root, uint64_t rank) {
        require(rank <= root.pages, "persistent split rank out of range");
        if (rank == 0) return {{}, root};
        if (rank == root.pages) return {root, {}};
        CowNode node = read(root);
        require(!node.leaf, "persistent split expected branch");
        if (rank < node.left.pages) {
            auto parts = split(node.left, rank);
            return {parts.first, join(parts.second, node.right)};
        }
        auto parts = split(node.right, rank - node.left.pages);
        return {join(node.left, parts.first), parts.second};
    }

    void snapshot(ImageHeader& header, const CowRef& root) const {
        CowIndexMeta meta{};
        std::memcpy(meta.magic, "ZIMCOW1\0", 8);
        meta.root = root;
        meta.created_node_bytes = created_bytes;
        meta.created_node_count = created_nodes;
        std::memset(header.reserved, 0, sizeof(header.reserved));
        std::memcpy(header.reserved, &meta, sizeof(meta));
        header.flags = (header.flags | kCowIndexFlag) & ~kPackedIndexFlag;
        header.page_count = root.pages;
        off_t tail = ::ftello(data_);
        syscheck(tail >= 0, "persistent committed data tail");
        header.index_offset = tail;
    }

    uint64_t created_bytes = 0;
    uint64_t created_nodes = 0;

private:
    struct CachedNode {
        CowRef ref{};
        CowNode node{};
    };

    CowRef write(const CowNode& node, uint64_t pages, uint32_t height) {
        Bytes bytes = encode_cow_node(node);
        off_t offset = ::ftello(data_);
        syscheck(offset >= 0, "persistent node append offset");
        CowRef ref{static_cast<uint64_t>(offset), static_cast<uint32_t>(bytes.size()), height, pages,
                   checksum(bytes.data(), bytes.size())};
        write_all(data_, bytes.data(), bytes.size());
        ++created_nodes;
        created_bytes += bytes.size();
        cache_[next_cache_] = {ref, node};
        next_cache_ = (next_cache_ + 1) % cache_.size();
        return ref;
    }

    CowRef branch(const CowRef& left, const CowRef& right) {
        if (!left.pages) return right;
        if (!right.pages) return left;
        require(std::abs(static_cast<int>(left.height) - static_cast<int>(right.height)) <= 1 &&
                left.pages <= std::numeric_limits<uint64_t>::max() - right.pages, "unbalanced persistent branch creation");
        CowNode node;
        node.left = left;
        node.right = right;
        return write(node, left.pages + right.pages, 1 + std::max(left.height, right.height));
    }

    CowRef balance(const CowRef& left, const CowRef& right) {
        if (!left.pages || !right.pages) return join(left, right);
        if (left.height > right.height + 1) {
            CowNode node = read(left);
            require(!node.leaf, "persistent rebalance expected left branch");
            if (node.left.height >= node.right.height)
                return branch(node.left, branch(node.right, right));
            CowNode middle = read(node.right);
            require(!middle.leaf, "persistent double rotation expected branch");
            return branch(branch(node.left, middle.left), branch(middle.right, right));
        }
        if (right.height > left.height + 1) {
            CowNode node = read(right);
            require(!node.leaf, "persistent rebalance expected right branch");
            if (node.right.height >= node.left.height)
                return branch(branch(left, node.left), node.right);
            CowNode middle = read(node.left);
            require(!middle.leaf, "persistent double rotation expected branch");
            return branch(branch(left, middle.left), branch(middle.right, node.right));
        }
        return branch(left, right);
    }

    FILE* data_;
    const Image* source_;
    std::array<CachedNode, 64> cache_{};
    size_t next_cache_ = 0;
};

class CowSequenceBuilder {
public:
    explicit CowSequenceBuilder(CowStore& store) : store_(store) {}

    void add(const PageIndex& page) {
        CowRef carry = store_.leaf(page);
        for (size_t level = 0; level < roots_.size(); ++level) {
            if (!roots_[level].pages) {
                roots_[level] = carry;
                return;
            }
            carry = store_.join(roots_[level], carry);
            roots_[level] = {};
        }
        throw std::runtime_error("persistent page sequence exceeds rank bound");
    }

    CowRef finish() {
        CowRef root{};
        for (size_t level = roots_.size(); level > 0; --level) {
            root = store_.join(root, roots_[level - 1]);
            roots_[level - 1] = {};
        }
        return root;
    }

private:
    CowStore& store_;
    std::array<CowRef, 64> roots_{};
};

std::string parent_name(const std::string& wire) {
    require(wire.size() > 1, "root has no parent");
    size_t first = static_cast<uint8_t>(wire[0]) + 1;
    require(first < wire.size(), "invalid name parent");
    return wire.substr(first);
}

unsigned parse_type(const std::string& input) {
    if (input == "ANY" || input == "0") return 0;
    if (input.rfind("TYPE", 0) == 0) {
        unsigned long value = std::stoul(input.substr(4));
        require(value <= 65535, "RR type out of range");
        return value;
    }
    bool numeric = !input.empty() && std::all_of(input.begin(), input.end(), [](char c) { return c >= '0' && c <= '9'; });
    if (numeric) {
        unsigned long value = std::stoul(input);
        require(value <= 65535, "RR type out of range");
        return value;
    }
    ldns_rr_type type = ldns_get_rr_type_by_name(input.c_str());
    require(type != 0, "unknown RR type " + input);
    return type;
}

void print_records(const std::vector<Record>& records, const std::string& origin,
                   const std::string* synthesized_owner = nullptr, uint32_t flags = 0) {
    std::cout << '[';
    bool first = true;
    for (const auto& record : records) {
        if (!first) std::cout << ',';
        first = false;
        std::string source_owner = owner_from_key(record.key, origin, flags);
        std::string owner = synthesized_owner ? *synthesized_owner : source_owner;
        std::cout << "{\"owner\":" << json_string(name_text(owner))
                  << ",\"source_owner\":" << json_string(name_text(source_owner))
                  << ",\"type\":" << record.type << ",\"class\":" << record.klass
                  << ",\"ttl\":" << record.ttl << ",\"multiplicity\":" << record.multiplicity
                  << ",\"rdata_hex\":" << json_string(hex(record.rdata))
                  << ",\"wire_hex\":" << json_string(hex(record_wire(record, origin, synthesized_owner, flags))) << '}';
    }
    std::cout << ']';
}

int query_command(const Options& options) {
    Image image(options.need("image"));
    uint32_t flags = image.header().flags;
    std::string qname = name_wire(options.need("name"));
    std::string key = make_key(qname, image.origin(), flags);
    unsigned type = parse_type(options.get("type", "A"));
    std::string state = image.name_state(key);
    auto located = image.lookup(key);
    std::string closest = qname;
    while (image.name_state(make_key(closest, image.origin(), flags)) == "absent" && closest != image.origin())
        closest = parent_name(closest);
    bool closest_exists = image.name_state(make_key(closest, image.origin(), flags)) != "absent";
    std::vector<std::string> ancestors;
    for (std::string ancestor = qname; ancestor != image.origin(); ancestor = parent_name(ancestor))
        ancestors.push_back(ancestor);
    std::string cut;
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it)
        if (image.has_type(make_key(*it, image.origin(), flags), 2)) { cut = *it; break; }
    auto exact = image.get_rrset(key, type);
    std::vector<Record> resolved;
    std::string wildcard;
    std::string status;
    bool synthesize = false;
    if (!cut.empty() && !(type == 43 && cut == qname)) {
        resolved = image.get_rrset(make_key(cut, image.origin(), flags), 2);
        status = "referral";
    } else if (state == "explicit") {
        resolved = exact;
        status = resolved.empty() ? "nodata" : "answer";
        if (resolved.empty() && type != 5 && type != 0) {
            resolved = image.get_rrset(key, 5);
            if (!resolved.empty()) status = "cname";
        }
    } else if (state == "ent") status = "nodata";
    else {
        if (closest_exists) {
            wildcard = std::string(1, '\1') + '*' + closest;
            std::string wildcard_key = make_key(wildcard, image.origin(), flags);
            if (image.name_state(wildcard_key) != "absent") {
                resolved = image.get_rrset(wildcard_key, type);
                if (resolved.empty() && type != 5 && type != 0) resolved = image.get_rrset(wildcard_key, 5);
                synthesize = true;
                status = resolved.empty() ? "nodata" : "answer";
            } else wildcard.clear();
        }
        if (wildcard.empty()) status = "nxdomain";
    }
    std::cout << "{\"origin\":" << json_string(name_text(image.origin()))
              << ",\"name\":" << json_string(name_text(qname)) << ",\"type\":" << type
              << ",\"name_state\":" << json_string(state)
              << ",\"lookup\":" << json_string(located.first) << ",\"lookup_owner\":";
    if (located.first == "none") std::cout << "null";
    else std::cout << json_string(name_text(owner_from_key(located.second, image.origin(), flags)));
    std::cout << ",\"closest_encloser\":";
    if (closest_exists) std::cout << json_string(name_text(closest)); else std::cout << "null";
    std::cout << ",\"wildcard_source\":" << (wildcard.empty() ? "null" : json_string(name_text(wildcard)))
              << ",\"zone_cut\":" << (cut.empty() ? "null" : json_string(name_text(cut)))
              << ",\"status\":" << json_string(status) << ",\"exact_records\":";
    print_records(exact, image.origin(), nullptr, flags);
    std::cout << ",\"records\":";
    print_records(resolved, image.origin(), synthesize ? &qname : nullptr, flags);
    std::cout << "}\n";
    return 0;
}

int build_command(const Options& options) {
    auto io_before = process_io();
    const auto overall_start = Clock::now();
    std::string origin_text = options.need("origin");
    std::string origin = name_wire(origin_text);
    fs::path out_path = options.need("out");
    fs::path work = options.need("work");
    require(!fs::exists(out_path), "output already exists");
    require(!fs::exists(work) || fs::is_empty(work), "work directory must be fresh");
    fs::create_directories(work);
    fs::create_directories(out_path.parent_path().empty() ? fs::path(".") : out_path.parent_path());
    unsigned long memory_mib = std::stoul(options.get("memory-mib", "16"));
    require(memory_mib >= 4 && memory_mib <= 4096, "memory-mib must be within 4..4096");
    unsigned long sort_memory_mib = std::stoul(options.get("sort-memory-mib", "1"));
    unsigned long sort_fan_in = std::stoul(options.get("sort-fan-in", "4"));
    require(sort_memory_mib >= 1 && sort_memory_mib <= memory_mib / 2,
            "sort-memory-mib must reserve at least half total workspace");
    require(sort_fan_in >= 2 && sort_fan_in <= 16, "sort-fan-in must be within 2..16");
    std::string sort_engine = options.get("sort-engine", "native");
    require(sort_engine == "native" || sort_engine == "gnu", "sort-engine must be native or gnu");
    unsigned long run_memory_mib = std::stoul(options.get("run-memory-mib", std::to_string(memory_mib / 4)));
    require(run_memory_mib >= 1 && run_memory_mib <= memory_mib / 2,
            "run-memory-mib must reserve at least half total workspace");
    std::string codec_name = options.get("codec", "none");
    unsigned codec = codec_name == "none" ? 0 : codec_name == "lz4" ? 1 : codec_name == "zstd" ? 2 : 999;
    require(codec <= 2, "codec must be none, lz4 or zstd");
    std::string pool_name = options.get("pool", "none");
    require(pool_name == "none" || pool_name == "local", "pool must be none or local");
    bool pool = pool_name == "local";
    std::string front_value = options.get("front-code", "1");
    require(front_value == "0" || front_value == "1", "front-code must be 0 or 1");
    bool front = front_value == "1";
    std::string index_format = options.get("index", "packed");
    require(index_format == "fixed" || index_format == "packed" || index_format == "cow", "index must be fixed, packed or cow");
    std::string key_codec = options.get("key-codec", "nibble");
    require(key_codec == "nibble" || key_codec == "compact", "key-codec must be nibble or compact");
    std::string next_key_value = options.get("nsec3-next-key", "0");
    require(next_key_value == "0" || next_key_value == "1", "nsec3-next-key must be 0 or 1");
    bool next_key = next_key_value == "1";
    uint32_t image_flags = (pool ? kPoolFlag : 0) | (front ? kFrontFlag : 0) |
                           (index_format == "packed" ? kPackedIndexFlag : 0) |
                           (index_format == "cow" ? kCowIndexFlag : 0) |
                           (key_codec == "compact" ? kCompactKeyFlag : 0) |
                           (next_key ? kNsec3NextKeyFlag : 0);
    require(options.get("zone").empty() != options.get("input-wire-hex").empty(),
            "choose exactly one zone or input-wire-hex");
    fs::path spool_path = work / "canonical_unsorted.tsv";
    fs::path sorted_path = work / "canonical_sorted.tsv";
    fs::path index_path = work / "page_index.bin";
    std::unique_ptr<NativeRunSorter> native_sorter;
    FILE* spool = nullptr;
    if (sort_engine == "native")
        native_sorter = std::make_unique<NativeRunSorter>(work, run_memory_mib, sort_fan_in);
    else {
        spool = std::fopen(spool_path.c_str(), "wb");
        syscheck(spool != nullptr, "open canonical spool");
        std::setvbuf(spool, nullptr, _IOFBF, 65536);
    }
    uint64_t occurrences = 0;
    auto parser_start = Clock::now();
    auto consume = [&](const std::string& wire) {
        auto record = record_from_wire(wire, origin, image_flags);
        if (native_sorter) native_sorter->add(record.key, wire);
        else {
            std::string row = hex(record.key) + '\t' + hex(wire) + '\n';
            write_all(spool, row.data(), row.size());
        }
        ++occurrences;
    };
    if (!options.get("zone").empty()) read_zone(options.get("zone"), origin_text, consume);
    else read_hex_lines(options.get("input-wire-hex"), consume);
    if (native_sorter) native_sorter->finish_runs();
    else syscheck(std::fclose(spool) == 0, "close canonical spool");
    double parser_seconds = seconds_since(parser_start);
    if (native_sorter) stage("parse_run_generation", parser_seconds,
        "\"rr_occurrences\":" + std::to_string(occurrences) +
        ",\"initial_runs\":" + std::to_string(native_sorter->initial_runs()) +
        ",\"arena_bytes\":" + std::to_string(native_sorter->arena_bytes()) +
        ",\"run_index_bytes\":" + std::to_string(native_sorter->index_bytes()) +
        ",\"nested_run_sort_write_seconds\":" + std::to_string(native_sorter->run_sort_write_seconds()));
    else stage("parse_canonical_spool", parser_seconds,
        "\"rr_occurrences\":" + std::to_string(occurrences) +
        ",\"spool_bytes\":" + std::to_string(fs::file_size(spool_path)));
    auto sort_start = Clock::now();
    if (native_sorter) native_sorter->prepare_merges();
    else run_sort(spool_path, sorted_path, work, sort_memory_mib, sort_fan_in);
    double sort_seconds = seconds_since(sort_start);
    if (native_sorter) stage("intermediate_merge", sort_seconds,
        "\"merge_passes\":" + std::to_string(native_sorter->intermediate_passes()) +
        ",\"merge_fan_in\":" + std::to_string(sort_fan_in));
    else stage("external_sort", sort_seconds,
        "\"sort_memory_mib\":" + std::to_string(sort_memory_mib) +
        ",\"sort_fan_in\":" + std::to_string(sort_fan_in));
    auto encode_start = Clock::now();
    fs::path temporary = out_path;
    temporary += ".tmp." + std::to_string(::getpid());
    int out_fd = ::open(temporary.c_str(), O_CREAT | O_EXCL | O_RDWR, 0644);
    syscheck(out_fd >= 0, "create temporary image");
    FILE* output = ::fdopen(out_fd, "w+b");
    syscheck(output != nullptr, "fdopen image");
    std::setvbuf(output, nullptr, _IOFBF, 65536);
    FILE* index_output = nullptr;
    if (index_format != "cow") {
        index_output = std::fopen(index_path.c_str(), "wb");
        syscheck(index_output != nullptr, "open page index");
    }
    ImageHeader header{};
    std::memcpy(header.magic, "ZIMDNS1\0", 8);
    header.version = kVersion;
    header.flags = image_flags;
    header.occurrences = occurrences;
    header.page_target = kPageTarget;
    header.requested_codec = codec;
    header.origin_length = origin.size();
    header.header_size = sizeof(header);
    std::memcpy(header.origin, origin.data(), origin.size());
    write_all(output, &header, sizeof(header));
    std::unique_ptr<CowStore> cow_store;
    std::unique_ptr<CowSequenceBuilder> cow_builder;
    if (index_format == "cow") {
        cow_store = std::make_unique<CowStore>(output);
        cow_builder = std::make_unique<CowSequenceBuilder>(*cow_store);
    }
    uint64_t decoded_total = 0, encoded_total = 0, compressed_pages = 0, plain_pages = 0;
    uint64_t owners = 0;
    std::string previous_owner;
    bool has_previous_owner = false;
    std::vector<Record> page_records;
    size_t page_estimate = 12;
    auto flush_page = [&]() {
        if (page_records.empty()) return;
        PageIndex entry = write_page_extent(output, page_records, header.flags, codec);
        if (cow_builder) cow_builder->add(entry);
        else write_all(index_output, &entry, sizeof(entry));
        decoded_total += entry.decoded_size;
        encoded_total += entry.encoded_size;
        if (entry.codec) ++compressed_pages; else ++plain_pages;
        ++header.page_count;
        page_records.clear();
        page_estimate = 12;
    };
    auto emit = [&](Record record) {
        size_t conservative = 40 + record.key.size() + stored_rdata_size(record, header.flags);
        if (!page_records.empty() && page_estimate + conservative > kPageTarget) flush_page();
        page_estimate += conservative;
        require(page_estimate <= kMaxPage, "single RR page exceeds bound");
        if (!has_previous_owner || previous_owner != record.key) {
            ++owners;
            previous_owner = record.key;
            has_previous_owner = true;
        }
        ++header.unique_records;
        page_records.push_back(std::move(record));
    };
    std::string previous_wire;
    std::string previous_sort_key;
    Record pending;
    bool has_pending = false;
    uint64_t observed_occurrences = 0;
    auto consume_sorted = [&](const std::string& sorted_key, const std::string& wire) {
        Record record = record_from_wire(wire, origin, image_flags);
        require(record.key == sorted_key, "canonical sort key mismatch");
        if (has_pending) require(!byte_less(sorted_key, previous_sort_key) &&
                                  (sorted_key != previous_sort_key || !byte_less(wire, previous_wire)),
                                  "external ordering comparator failure");
        ++observed_occurrences;
        if (has_pending && wire == previous_wire) {
            require(pending.multiplicity != std::numeric_limits<uint64_t>::max(), "multiplicity overflow");
            ++pending.multiplicity;
        } else {
            if (has_pending) emit(std::move(pending));
            pending = std::move(record);
            previous_wire = wire;
            previous_sort_key = sorted_key;
            has_pending = true;
        }
    };
    if (native_sorter) native_sorter->final_merge([&](const SortFrame& frame) {
        consume_sorted(frame.key, frame.wire);
    });
    else {
        FILE* sorted = std::fopen(sorted_path.c_str(), "rb");
        syscheck(sorted != nullptr, "open sorted stream");
        std::vector<char> line(kMaxSortLine);
        while (std::fgets(line.data(), line.size(), sorted)) {
            size_t length = std::strlen(line.data());
            require(length && line[length - 1] == '\n', "sort record exceeds protocol bound");
            --length;
            const char* tab = static_cast<const char*>(std::memchr(line.data(), '\t', length));
            require(tab != nullptr, "malformed canonical spool");
            size_t key_hex_length = tab - line.data();
            consume_sorted(unhex(line.data(), key_hex_length), unhex(tab + 1, length - key_hex_length - 1));
        }
        require(!std::ferror(sorted), "sorted stream read error");
        std::fclose(sorted);
    }
    require(observed_occurrences == occurrences, "sort lost RR occurrences");
    if (has_pending) emit(std::move(pending));
    flush_page();
    uint64_t index_bytes = 0;
    if (cow_builder) {
        CowRef root = cow_builder->finish();
        cow_store->snapshot(header, root);
        index_bytes = cow_store->created_bytes;
    } else {
        syscheck(std::fclose(index_output) == 0, "close page index");
        off_t index_offset = ::ftello(output);
        syscheck(index_offset >= 0, "index output offset");
        header.index_offset = index_offset;
        index_bytes = append_final_index(output, index_path, header);
    }
    syscheck(::fseeko(output, 0, SEEK_SET) == 0, "seek final header");
    write_all(output, &header, sizeof(header));
    syscheck(std::fflush(output) == 0, "flush final image");
    double encode_seconds = seconds_since(encode_start);
    stage(native_sorter ? "final_merge_encode" : "encode_image", encode_seconds,
          "\"pages\":" + std::to_string(header.page_count) + ",\"unique_records\":" + std::to_string(header.unique_records));
    auto sync_start = Clock::now();
    syscheck(::fsync(out_fd) == 0, "fsync image");
    syscheck(std::fclose(output) == 0, "close image");
    syscheck(::link(temporary.c_str(), out_path.c_str()) == 0, "publish exclusive image");
    syscheck(::unlink(temporary.c_str()) == 0, "remove temporary image name");
    sync_directory(out_path.parent_path());
    double sync_seconds = seconds_since(sync_start);
    stage("fsync_publish", sync_seconds);
    auto io_after = process_io();
    std::string io_delta = "{";
    bool first_counter = true;
    for (const auto& counter : io_after) {
        auto before = io_before.find(counter.first);
        require(before != io_before.end() && counter.second >= before->second, "process IO counter decreased");
        if (!first_counter) io_delta += ',';
        first_counter = false;
        io_delta += json_string(counter.first) + ':' + std::to_string(counter.second - before->second);
    }
    io_delta += '}';
    struct rusage usage{};
    ::getrusage(RUSAGE_SELF, &usage);
    std::string summary = "{\"status\":\"BUILT_PENDING_EXTERNAL_VALIDATION\",\"format\":\"ZIMDNS1\","
        "\"origin\":" + json_string(name_text(origin)) + ",\"input_model\":\"unordered_external_sort\","
        "\"memory_mib\":" + std::to_string(memory_mib) + ",\"sort_memory_mib\":" + std::to_string(sort_memory_mib) +
        ",\"sort_fan_in\":" + std::to_string(sort_fan_in) +
        ",\"sort_engine\":" + json_string(sort_engine) +
        ",\"run_memory_mib\":" + std::to_string(run_memory_mib) +
        ",\"run_sort_write_seconds_nested_in_parse\":" +
             std::to_string(native_sorter ? native_sorter->run_sort_write_seconds() : 0) +
        ",\"initial_runs\":" + std::to_string(native_sorter ? native_sorter->initial_runs() : 0) +
        ",\"intermediate_merge_passes\":" + std::to_string(native_sorter ? native_sorter->intermediate_passes() : 0) +
        ",\"codec\":" + json_string(codec_name) + ",\"pool\":" + json_string(pool_name) + ",\"front_code\":" + (front ? "true" : "false") +
        ",\"index_format\":" + json_string(index_format) +
        ",\"key_codec\":" + json_string(key_codec) +
        ",\"nsec3_next_key\":" + (next_key ? "true" : "false") +
        ",\"rr_occurrences\":" + std::to_string(occurrences) + ",\"unique_rrs\":" + std::to_string(header.unique_records) +
        ",\"owners\":" + std::to_string(owners) + ",\"pages\":" + std::to_string(header.page_count) +
        ",\"decoded_page_bytes\":" + std::to_string(decoded_total) + ",\"encoded_page_bytes\":" + std::to_string(encoded_total) +
        ",\"index_bytes\":" + std::to_string(index_bytes) +
        ",\"fixed_index_staging_bytes\":" + std::to_string(cow_builder ? 0 : header.page_count * sizeof(PageIndex)) +
        ",\"created_index_nodes\":" + std::to_string(cow_store ? cow_store->created_nodes : 0) +
        ",\"image_bytes\":" + std::to_string(fs::file_size(out_path)) +
        ",\"compressed_pages\":" + std::to_string(compressed_pages) + ",\"plain_pages\":" + std::to_string(plain_pages) +
        ",\"process_io_delta\":" + io_delta +
        ",\"parse_seconds\":" + std::to_string(parser_seconds) + ",\"sort_seconds\":" + std::to_string(sort_seconds) +
        ",\"encode_seconds\":" + std::to_string(encode_seconds) + ",\"fsync_seconds\":" + std::to_string(sync_seconds) +
        ",\"total_seconds\":" + std::to_string(seconds_since(overall_start)) + ",\"self_hwm_kib\":" + std::to_string(usage.ru_maxrss) + "}";
    if (!options.get("stats").empty()) {
        std::ofstream stats(options.get("stats"));
        require(stats.good(), "open stats output failed");
        stats << summary << '\n';
        stats.close();
        require(stats.good(), "write stats failed");
    }
    std::cerr << "SUMMARY " << summary << '\n';
    return 0;
}

struct DirtyInterval {
    uint64_t first;
    uint64_t end;
};

DirtyInterval dirty_interval(const Image& image, const std::string& key) {
    if (image.header().page_count == 0) return {0, 0};
    uint64_t first = image.first_possible_page(key);
    uint64_t lo = 0, hi = image.header().page_count;
    while (lo < hi) {
        uint64_t middle = lo + (hi - lo) / 2;
        if (!byte_less(key, index_key(image.index(middle)))) lo = middle + 1;
        else hi = middle;
    }
    return {first, std::max(first + 1, lo)};
}

struct DeltaIdentity {
    struct stat state{};
    std::string sha256;
};

bool same_delta_file(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino && left.st_size == right.st_size &&
           left.st_mtim.tv_sec == right.st_mtim.tv_sec && left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
           left.st_ctim.tv_sec == right.st_ctim.tv_sec && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

DeltaIdentity read_owner_delta(const std::string& path, const std::string& origin,
    const std::function<void(const std::string&, const std::string&, char)>& consume,
    uint32_t flags = 0, const DeltaIdentity* expected = nullptr) {
    std::unique_ptr<FILE, int (*)(FILE*)> input(std::fopen(path.c_str(), "rb"), &std::fclose);
    syscheck(input != nullptr, "open owner-ordered delta");
    DeltaIdentity identity;
    syscheck(::fstat(::fileno(input.get()), &identity.state) == 0, "stat owner-ordered delta");
    if (expected) require(same_delta_file(identity.state, expected->state), "delta file identity changed between passes");
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    require(digest != nullptr && EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) == 1,
            "initialize delta SHA256");
    std::vector<char> line(2 * kMaxWire + 8);
    std::string previous_key;
    bool previous = false;
    while (std::fgets(line.data(), line.size(), input.get())) {
        size_t length = std::strlen(line.data());
        require(length && line[length - 1] == '\n', "delta line exceeds protocol bound or lacks newline");
        require(EVP_DigestUpdate(digest.get(), line.data(), length) == 1, "update delta SHA256");
        --length;
        if (length && line[length - 1] == '\r') --length;
        if (!length) continue;
        require(length >= 2 && (line[0] == '+' || line[0] == '-') && line[1] == '\t', "invalid delta operation");
        std::string wire = recanonicalize_wire(unhex(line.data() + 2, length - 2));
        Record record = record_from_wire(wire, origin, flags);
        require(!previous || !byte_less(record.key, previous_key), "delta owner order is not monotone");
        previous_key = record.key;
        previous = true;
        consume(record.key, wire, line[0]);
    }
    require(!std::ferror(input.get()), "owner-ordered delta read error");
    struct stat after{};
    syscheck(::fstat(::fileno(input.get()), &after) == 0, "stat delta after complete read");
    require(same_delta_file(identity.state, after), "delta file changed during a pass");
    std::array<uint8_t, EVP_MAX_MD_SIZE> bytes{};
    unsigned length = 0;
    require(EVP_DigestFinal_ex(digest.get(), bytes.data(), &length) == 1 && length == 32, "finalize delta SHA256");
    identity.sha256 = hex(bytes.data(), length);
    if (expected) require(identity.sha256 == expected->sha256, "delta SHA256 changed between passes");
    return identity;
}

class OwnerPageCursor {
public:
    explicit OwnerPageCursor(const Image& source) : source_(source) {}

    DirtyInterval locate(const std::string& key) {
        if (source_.header().page_count == 0) return {0, 0};
        if (!initialized_) {
            page_ = source_.first_possible_page(key);
            initialized_ = true;
            load();
        }
        while (page_ < source_.header().page_count && byte_less(key_, key)) advance();
        uint64_t first = page_ == 0 ? 0 : page_ - 1;
        while (page_ < source_.header().page_count && key_ == key) advance();
        return {first, std::max(first + 1, page_)};
    }

    uint64_t page_reads = 0;

private:
    void load() {
        if (page_ < source_.header().page_count) {
            key_ = index_key(source_.index(page_));
            ++page_reads;
        } else key_.clear();
    }

    void advance() { ++page_; load(); }

    const Image& source_;
    uint64_t page_ = 0;
    bool initialized_ = false;
    std::string key_;
};

class BaseIntervalCursor {
public:
    BaseIntervalCursor(const Image& image, DirtyInterval interval)
        : image_(image), next_page_(interval.first), end_page_(interval.end) {
        advance();
    }

    bool available() const { return available_; }
    const Record& record() const { return page_[record_index_]; }
    const std::string& wire() const { return wire_; }
    uint64_t consumed_records() const { return consumed_records_; }

    void advance() {
        if (available_) { ++record_index_; ++consumed_records_; }
        while (record_index_ >= page_.size()) {
            if (next_page_ == end_page_) {
                available_ = false;
                page_.clear();
                wire_.clear();
                return;
            }
            page_ = image_.page(next_page_++);
            record_index_ = 0;
        }
        available_ = true;
        wire_ = record_wire(record(), image_.origin(), nullptr, image_.header().flags);
    }

private:
    const Image& image_;
    uint64_t next_page_;
    uint64_t end_page_;
    std::vector<Record> page_;
    size_t record_index_ = 0;
    bool available_ = false;
    std::string wire_;
    uint64_t consumed_records_ = 0;
};

class UpdatePageWriter {
public:
    UpdatePageWriter(FILE* data, FILE* index, uint32_t flags, unsigned codec, CowStore* cow_store = nullptr)
        : data_(data), index_(index), flags_(flags), codec_(codec) {
        if (cow_store) cow_builder_ = std::make_unique<CowSequenceBuilder>(*cow_store);
    }

    void add(const Record& record) {
        size_t conservative = 40 + record.key.size() + stored_rdata_size(record, flags_);
        if (!records_.empty() && estimate_ + conservative > kPageTarget) flush();
        estimate_ += conservative;
        require(estimate_ <= kMaxPage, "updated RR page exceeds protocol bound");
        records_.push_back(record);
    }

    void flush() {
        if (records_.empty()) return;
        PageIndex descriptor = write_page_extent(data_, records_, flags_, codec_);
        if (cow_builder_) cow_builder_->add(descriptor);
        else write_all(index_, &descriptor, sizeof(descriptor));
        ++new_pages;
        ++pages;
        entries += descriptor.record_count;
        new_page_bytes += descriptor.encoded_size;
        records_.clear();
        estimate_ = 12;
    }

    void reuse(const PageIndex& descriptor) {
        require(!cow_builder_, "persistent index must reuse whole subtrees");
        flush();
        write_all(index_, &descriptor, sizeof(descriptor));
        ++reused_pages;
        ++pages;
        entries += descriptor.record_count;
    }

    CowRef replacement_root() {
        require(cow_builder_ != nullptr, "replacement root requires persistent index");
        flush();
        return cow_builder_->finish();
    }

    uint64_t pages = 0;
    uint64_t entries = 0;
    uint64_t new_pages = 0;
    uint64_t reused_pages = 0;
    uint64_t new_page_bytes = 0;

private:
    FILE* data_;
    FILE* index_;
    uint32_t flags_;
    unsigned codec_;
    std::vector<Record> records_;
    size_t estimate_ = 12;
    std::unique_ptr<CowSequenceBuilder> cow_builder_;
};

uint64_t publish_file(const fs::path& destination, const Bytes& bytes, bool replace) {
    fs::create_directories(destination.parent_path().empty() ? fs::path(".") : destination.parent_path());
    fs::path temporary = destination;
    temporary += ".tmp." + std::to_string(::getpid());
    int descriptor = ::open(temporary.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
    syscheck(descriptor >= 0, "create publication temporary");
    size_t done = 0;
    while (done < bytes.size()) {
        ssize_t written = ::write(descriptor, bytes.data() + done, bytes.size() - done);
        if (written < 0 && errno == EINTR) continue;
        syscheck(written > 0, "write publication temporary");
        done += written;
    }
    syscheck(::fsync(descriptor) == 0, "fsync publication temporary");
    syscheck(::close(descriptor) == 0, "close publication temporary");
    if (replace) syscheck(::rename(temporary.c_str(), destination.c_str()) == 0, "rename CURRENT");
    else {
        syscheck(::link(temporary.c_str(), destination.c_str()) == 0, "publish exclusive generation");
        syscheck(::unlink(temporary.c_str()) == 0, "remove generation temporary name");
    }
    sync_directory(destination.parent_path());
    return bytes.size();
}

Bytes generation_descriptor(const fs::path& destination, const fs::path& data_file,
                             const ImageHeader& snapshot) {
    fs::path parent = destination.parent_path().empty() ? fs::path(".") : destination.parent_path();
    std::string relative = fs::relative(data_file, parent).generic_string();
    require(!relative.empty() && relative.size() <= 4096, "generation data path too long");
    GenerationHeader descriptor{};
    std::memcpy(descriptor.magic, "ZIMGEN1\0", 8);
    descriptor.version = 1;
    descriptor.path_length = relative.size();
    descriptor.snapshot = snapshot;
    Bytes bytes(sizeof(descriptor) + relative.size());
    std::memcpy(bytes.data(), &descriptor, sizeof(descriptor));
    std::memcpy(bytes.data() + sizeof(descriptor), relative.data(), relative.size());
    uint64_t hash = checksum(bytes.data(), bytes.size());
    const uint8_t* raw_hash = reinterpret_cast<const uint8_t*>(&hash);
    bytes.insert(bytes.end(), raw_hash, raw_hash + sizeof(hash));
    return bytes;
}

void check_current(const Options& options, const Image& source) {
    fs::path current_path = options.get("current");
    if (current_path.empty() || !fs::exists(current_path)) return;
    fs::path selected = resolve_snapshot_path(current_path, true);
    require(fs::equivalent(selected, source.snapshot_path()), "CURRENT generation conflict");
}

int update_command(const Options& options) {
    auto io_before = process_io();
    auto total_start = Clock::now();
    fs::path out = fs::absolute(options.need("out")).lexically_normal();
    std::string current_destination = options.get("current");
    require(current_destination.empty() || fs::absolute(current_destination).lexically_normal() != out,
            "generation output and CURRENT must be distinct paths");
    fs::path work = options.need("work");
    require(!fs::exists(out), "generation output already exists");
    require(!fs::exists(work) || fs::is_empty(work), "update work directory must be fresh");
    fs::create_directories(work);
    fs::create_directories(out.parent_path());
    unsigned long memory_mib = std::stoul(options.get("memory-mib", "16"));
    unsigned long run_memory_mib = std::stoul(options.get("run-memory-mib", std::to_string(memory_mib / 4)));
    unsigned long fan_in = std::stoul(options.get("sort-fan-in", "4"));
    require(memory_mib >= 4 && memory_mib <= 4096 && run_memory_mib >= 1 &&
            run_memory_mib <= memory_mib / 2 && fan_in >= 2 && fan_in <= 16, "invalid update workspace budget");
    Image source(options.need("image"));
    bool cow_mode = source.header().flags & kCowIndexFlag;
    std::string source_index = cow_mode ? "cow" : (source.header().flags & kPackedIndexFlag ? "packed" : "fixed");
    require(options.get("index", source_index) == source_index, "update index encoding must match its base generation");
    std::string source_key_codec = source.header().flags & kCompactKeyFlag ? "compact" : "nibble";
    require(options.get("key-codec", source_key_codec) == source_key_codec, "update key codec must match its base generation");
    bool source_next_key = source.header().flags & kNsec3NextKeyFlag;
    require(options.get("nsec3-next-key", source_next_key ? "1" : "0") == (source_next_key ? "1" : "0"),
            "update NSEC3 next encoding must match its base generation");
    std::string delta_order = options.get("delta-order", "unordered");
    require(delta_order == "unordered" || delta_order == "owner", "delta-order must be unordered or owner");
    bool owner_ordered = delta_order == "owner";
    int data_fd = ::open(source.data_path().c_str(), O_RDWR);
    syscheck(data_fd >= 0, "open generation data for append");
    syscheck(::flock(data_fd, LOCK_EX) == 0, "lock generation writer");
    check_current(options, source);
    struct stat old_stat{};
    syscheck(::fstat(data_fd, &old_stat) == 0, "stat original data file");
    uint64_t old_data_bytes = old_stat.st_size;
    NativeRunSorter sorter(work, run_memory_mib, fan_in);
    uint64_t additions = 0, removals = 0;
    fs::path intervals_path = work / "dirty_intervals.bin";
    FILE* intervals_output = std::fopen(intervals_path.c_str(), "wb");
    syscheck(intervals_output != nullptr, "open dirty interval output");
    DirtyInterval pending_interval{};
    bool has_interval = false;
    bool has_previous_key = false;
    std::string previous_key;
    uint64_t dirty_owner_count = 0, interval_count = 0, dirty_pages = 0;
    OwnerPageCursor page_cursor(source);
    auto flush_interval = [&]() {
        if (!has_interval) return;
        write_all(intervals_output, &pending_interval, sizeof(pending_interval));
        dirty_pages += pending_interval.end - pending_interval.first;
        ++interval_count;
    };
    auto plan_owner = [&](const std::string& key) {
        if (has_previous_key && key == previous_key) return;
        previous_key = key;
        has_previous_key = true;
        ++dirty_owner_count;
        DirtyInterval interval = owner_ordered ? page_cursor.locate(key) : dirty_interval(source, key);
        if (!has_interval) {
            pending_interval = interval;
            has_interval = true;
        } else if (interval.first <= pending_interval.end)
            pending_interval.end = std::max(pending_interval.end, interval.end);
        else {
            flush_interval();
            pending_interval = interval;
        }
    };
    DeltaIdentity delta_identity;
    auto parse_start = Clock::now();
    if (owner_ordered) {
        delta_identity = read_owner_delta(options.need("delta"), source.origin(),
            [&](const std::string& key, const std::string&, char operation) {
                if (operation == '+') ++additions; else ++removals;
                plan_owner(key);
            }, source.header().flags);
    } else {
        FILE* delta_input = std::fopen(options.need("delta").c_str(), "rb");
        syscheck(delta_input != nullptr, "open delta");
        std::vector<char> line(2 * kMaxWire + 8);
        while (std::fgets(line.data(), line.size(), delta_input)) {
            size_t length = std::strlen(line.data());
            require(length && line[length - 1] == '\n', "delta line exceeds protocol bound or lacks newline");
            --length;
            if (length && line[length - 1] == '\r') --length;
            if (!length) continue;
            require(length >= 2 && (line[0] == '+' || line[0] == '-') && line[1] == '\t', "invalid delta operation");
            std::string wire = recanonicalize_wire(unhex(line.data() + 2, length - 2));
            auto record = record_from_wire(wire, source.origin(), source.header().flags);
            wire.push_back(line[0]);
            sorter.add(record.key, wire);
            if (line[0] == '+') ++additions; else ++removals;
        }
        require(!std::ferror(delta_input), "delta read error");
        std::fclose(delta_input);
        sorter.finish_runs();
    }
    double parse_seconds = seconds_since(parse_start);
    stage(owner_ordered ? "delta_owner_validate_intervals" : "delta_parse_run_generation", parse_seconds,
          "\"delta_order\":" + json_string(delta_order) +
          ",\"add_occurrences\":" + std::to_string(additions) +
          ",\"remove_occurrences\":" + std::to_string(removals));
    auto order_start = Clock::now();
    if (!owner_ordered) {
        sorter.prepare_merges();
        sorter.final_merge([&](const SortFrame& frame) { plan_owner(frame.key); });
    }
    flush_interval();
    syscheck(std::fclose(intervals_output) == 0, "close dirty interval output");
    double order_seconds = seconds_since(order_start);
    stage("delta_order_intervals", order_seconds,
          "\"dirty_owners\":" + std::to_string(dirty_owner_count) +
          ",\"dirty_source_pages\":" + std::to_string(dirty_pages) +
          ",\"dirty_intervals\":" + std::to_string(interval_count) +
          ",\"owner_cursor_page_reads\":" + std::to_string(page_cursor.page_reads));
    auto encode_start = Clock::now();
    FILE* output = ::fdopen(data_fd, "r+b");
    syscheck(output != nullptr, "fdopen generation data");
    std::setvbuf(output, nullptr, _IOFBF, 65536);
    syscheck(::fseeko(output, 0, SEEK_END) == 0, "seek generation append position");
    fs::path new_index_path = work / "generation_index.bin";
    FILE* new_index = nullptr;
    std::unique_ptr<CowStore> cow_store;
    CowRef cow_remaining{}, cow_result{};
    if (cow_mode) {
        cow_store = std::make_unique<CowStore>(output, &source);
        cow_remaining = source.cow_root();
    } else {
        new_index = std::fopen(new_index_path.c_str(), "wb");
        syscheck(new_index != nullptr, "open generation index");
    }
    UpdatePageWriter writer(output, new_index, source.header().flags, source.header().requested_codec, cow_store.get());
    FILE* intervals_input = std::fopen(intervals_path.c_str(), "rb");
    syscheck(intervals_input != nullptr, "read dirty interval input");
    uint64_t source_page = 0;
    DirtyInterval current_interval{};
    bool interval_active = false;
    std::unique_ptr<BaseIntervalCursor> base_cursor;
    uint64_t reencoded_owners = 0;
    uint64_t dirty_old_entries = 0;
    std::string last_reencoded_owner;
    bool has_reencoded_owner = false;
    auto touch_owner = [&](const std::string& key) {
        if (!has_reencoded_owner || key != last_reencoded_owner) {
            ++reencoded_owners;
            last_reencoded_owner = key;
            has_reencoded_owner = true;
        }
    };
    auto start_interval = [&]() {
        if (std::fread(&current_interval, sizeof(current_interval), 1, intervals_input) != 1) {
            require(!std::ferror(intervals_input), "dirty interval read failure");
            interval_active = false;
            return;
        }
        require(current_interval.first >= source_page && current_interval.end >= current_interval.first &&
                current_interval.end <= source.header().page_count, "invalid dirty page interval");
        if (cow_store) {
            auto clean = cow_store->split(cow_remaining, current_interval.first - source_page);
            cow_result = cow_store->join(cow_result, clean.first);
            auto dirty = cow_store->split(clean.second, current_interval.end - current_interval.first);
            cow_remaining = dirty.second;
            source_page = current_interval.first;
        } else while (source_page < current_interval.first) writer.reuse(source.index(source_page++));
        base_cursor = std::make_unique<BaseIntervalCursor>(source, current_interval);
        interval_active = true;
    };
    auto finish_interval = [&]() {
        if (!interval_active) return;
        while (base_cursor->available()) {
            touch_owner(base_cursor->record().key);
            writer.add(base_cursor->record());
            base_cursor->advance();
        }
        if (cow_store) cow_result = cow_store->join(cow_result, writer.replacement_root());
        else writer.flush();
        dirty_old_entries += base_cursor->consumed_records();
        source_page = current_interval.end;
        base_cursor.reset();
        interval_active = false;
    };
    start_interval();
    uint64_t group_adds = 0, group_removes = 0;
    std::string group_key, group_wire;
    bool has_group = false;
    auto apply_group = [&]() {
        if (!has_group) return;
        while (interval_active && current_interval.end < source.header().page_count &&
               !byte_less(group_key, index_key(source.index(current_interval.end)))) {
            finish_interval();
            start_interval();
        }
        require(interval_active, "delta is outside computed dirty intervals");
        auto base_less = [&]() -> bool {
            if (!base_cursor->available()) return false;
            const std::string& base_key = base_cursor->record().key;
            if (base_key != group_key) return byte_less(base_key, group_key);
            return byte_less(base_cursor->wire(), group_wire);
        };
        while (base_less()) {
            touch_owner(base_cursor->record().key);
            writer.add(base_cursor->record());
            base_cursor->advance();
        }
        Record changed = record_from_wire(group_wire, source.origin(), source.header().flags);
        uint64_t old_count = 0;
        bool matches = base_cursor->available() && base_cursor->record().key == group_key &&
                       base_cursor->wire() == group_wire;
        if (matches) old_count = base_cursor->record().multiplicity;
        require(group_removes <= old_count, "delta removes absent RR occurrence");
        require(group_adds <= std::numeric_limits<uint64_t>::max() - (old_count - group_removes),
                "delta multiplicity overflow");
        touch_owner(group_key);
        changed.multiplicity = old_count - group_removes + group_adds;
        if (changed.multiplicity) writer.add(changed);
        if (matches) base_cursor->advance();
    };
    auto consume_ordered_operation = [&](const SortFrame& frame) {
        require(!frame.wire.empty() && (frame.wire.back() == '+' || frame.wire.back() == '-'),
                "invalid ordered delta operation");
        std::string wire = frame.wire.substr(0, frame.wire.size() - 1);
        if (!has_group || frame.key != group_key || wire != group_wire) {
            apply_group();
            group_key = frame.key;
            group_wire = std::move(wire);
            group_adds = group_removes = 0;
            has_group = true;
        }
        if (frame.wire.back() == '+') ++group_adds; else ++group_removes;
    };
    uint64_t in_memory_owners = 0, spilled_owners = 0, maximum_owner_operations = 0;
    bool delta_identity_verified = false;
    if (owner_ordered) {
        std::string member_owner;
        bool has_member_owner = false;
        uint64_t owner_operations = 0;
        auto finish_owner = [&]() {
            if (!has_member_owner) return;
            bool spilled = sorter.finish_owner(consume_ordered_operation);
            if (spilled) ++spilled_owners; else ++in_memory_owners;
            maximum_owner_operations = std::max(maximum_owner_operations, owner_operations);
            owner_operations = 0;
        };
        read_owner_delta(options.need("delta"), source.origin(),
            [&](const std::string& key, const std::string& wire, char operation) {
                if (has_member_owner && key != member_owner) finish_owner();
                member_owner = key;
                has_member_owner = true;
                std::string ordered_wire = wire;
                ordered_wire.push_back(operation);
                sorter.add(key, ordered_wire);
                ++owner_operations;
            }, source.header().flags, &delta_identity);
        delta_identity_verified = true;
        finish_owner();
    } else sorter.final_merge(consume_ordered_operation);
    apply_group();
    while (interval_active) {
        finish_interval();
        start_interval();
    }
    if (cow_store) {
        cow_result = cow_store->join(cow_result, cow_remaining);
        writer.reused_pages = source.header().page_count - dirty_pages;
    } else while (source_page < source.header().page_count) writer.reuse(source.index(source_page++));
    writer.flush();
    syscheck(std::fclose(intervals_input) == 0, "close dirty interval input");
    if (new_index) syscheck(std::fclose(new_index) == 0, "close generation index");
    ImageHeader snapshot = source.header();
    uint64_t rewritten_index_bytes = 0;
    if (cow_store) {
        cow_store->snapshot(snapshot, cow_result);
        require(dirty_old_entries <= source.header().unique_records, "dirty source RR count overflow");
        snapshot.unique_records = source.header().unique_records - dirty_old_entries + writer.entries;
        rewritten_index_bytes = cow_store->created_bytes;
    } else {
        off_t index_offset = ::ftello(output);
        syscheck(index_offset >= 0, "new generation index offset");
        snapshot.index_offset = index_offset;
        snapshot.page_count = writer.pages;
        snapshot.unique_records = writer.entries;
        rewritten_index_bytes = append_final_index(output, new_index_path, snapshot);
    }
    require(removals <= snapshot.occurrences &&
            additions <= std::numeric_limits<uint64_t>::max() - (snapshot.occurrences - removals),
            "delta total occurrence overflow");
    snapshot.occurrences = snapshot.occurrences - removals + additions;
    syscheck(std::fflush(output) == 0, "flush updated data file");
    double encode_seconds = seconds_since(encode_start);
    stage("dirty_interval_reencode", encode_seconds,
          "\"reencoded_owners\":" + std::to_string(reencoded_owners) +
          ",\"new_page_bytes\":" + std::to_string(writer.new_page_bytes) +
          ",\"new_index_bytes\":" + std::to_string(rewritten_index_bytes));
    auto publish_start = Clock::now();
    syscheck(::fsync(data_fd) == 0, "fsync appended generation data");
    sync_directory(source.data_path().parent_path());
    require(options.get("fail-before-publish", "0") != "1", "injected failure before generation publication");
    Bytes descriptor = generation_descriptor(out, source.data_path(), snapshot);
    uint64_t descriptor_bytes = publish_file(out, descriptor, false);
    uint64_t current_bytes = 0;
    if (!options.get("current").empty()) {
        require(options.get("fail-before-current", "0") != "1", "injected failure before CURRENT publication");
        fs::path current_path = fs::absolute(options.get("current")).lexically_normal();
        fs::path current_parent = current_path.parent_path().empty() ? fs::path(".") : current_path.parent_path();
        fs::create_directories(current_parent);
        std::string relative = fs::relative(out, current_parent).generic_string() + '\n';
        Bytes current_content(relative.begin(), relative.end());
        current_bytes = publish_file(current_path, current_content, true);
    }
    struct stat new_stat{};
    syscheck(::fstat(data_fd, &new_stat) == 0, "stat updated data file");
    syscheck(std::fclose(output) == 0, "close generation writer");
    double publish_seconds = seconds_since(publish_start);
    stage("generation_fsync_publish", publish_seconds);
    auto io_after = process_io();
    std::string io_delta = "{";
    bool first_counter = true;
    for (const auto& counter : io_after) {
        auto before = io_before.find(counter.first);
        require(before != io_before.end() && counter.second >= before->second, "process IO counter decreased");
        if (!first_counter) io_delta += ',';
        first_counter = false;
        io_delta += json_string(counter.first) + ':' + std::to_string(counter.second - before->second);
    }
    io_delta += '}';
    uint64_t data_growth = static_cast<uint64_t>(new_stat.st_size) - old_data_bytes;
    uint64_t rewrite_bytes = data_growth + descriptor_bytes + current_bytes;
    struct rusage usage{};
    ::getrusage(RUSAGE_SELF, &usage);
    std::string summary = "{\"status\":\"UPDATED_PENDING_EXTERNAL_VALIDATION\",\"format\":\"ZIMGEN1\","
        "\"data_file\":" + json_string(source.data_path().string()) + ",\"generation\":" + json_string(out.string()) +
        ",\"delta_order\":" + json_string(delta_order) +
        ",\"delta_file_passes\":" + std::to_string(owner_ordered ? 2 : 1) +
        ",\"delta_source_sha256\":" + (owner_ordered ? json_string(delta_identity.sha256) : "null") +
        ",\"delta_pass_identity_verified\":" + (delta_identity_verified ? "true" : "false") +
        ",\"owner_cursor_page_reads\":" + std::to_string(page_cursor.page_reads) +
        ",\"in_memory_sorted_owners\":" + std::to_string(in_memory_owners) +
        ",\"spilled_sorted_owners\":" + std::to_string(spilled_owners) +
        ",\"maximum_owner_operations\":" + std::to_string(maximum_owner_operations) +
        ",\"generated_delta_runs\":" + std::to_string(sorter.initial_runs()) +
        ",\"owner_memory_sort_seconds\":" + std::to_string(sorter.memory_sort_seconds()) +
        ",\"delta_run_sort_write_seconds\":" + std::to_string(sorter.run_sort_write_seconds()) +
        ",\"memory_mib\":" + std::to_string(memory_mib) + ",\"run_memory_mib\":" + std::to_string(run_memory_mib) +
        ",\"merge_fan_in\":" + std::to_string(fan_in) + ",\"delta_add_occurrences\":" + std::to_string(additions) +
        ",\"delta_remove_occurrences\":" + std::to_string(removals) + ",\"dirty_owners\":" + std::to_string(dirty_owner_count) +
        ",\"dirty_source_pages\":" + std::to_string(dirty_pages) + ",\"dirty_intervals\":" + std::to_string(interval_count) +
        ",\"reencoded_owners\":" + std::to_string(reencoded_owners) + ",\"new_pages\":" + std::to_string(writer.new_pages) +
        ",\"reused_pages\":" + std::to_string(writer.reused_pages) + ",\"new_page_bytes\":" + std::to_string(writer.new_page_bytes) +
        ",\"index_rewrite_bytes\":" + std::to_string(rewritten_index_bytes) +
        ",\"fixed_index_staging_bytes\":" + std::to_string(cow_store ? 0 : snapshot.page_count * sizeof(PageIndex)) +
        ",\"created_index_nodes\":" + std::to_string(cow_store ? cow_store->created_nodes : 0) +
        ",\"index_format\":" + json_string(source_index) +
        ",\"key_codec\":" + json_string(source_key_codec) +
        ",\"nsec3_next_key\":" + (source_next_key ? "true" : "false") +
        ",\"descriptor_bytes\":" + std::to_string(descriptor_bytes) + ",\"current_payload_bytes\":" + std::to_string(current_bytes) +
        ",\"rewrite_bytes\":" + std::to_string(rewrite_bytes) + ",\"data_growth_bytes\":" + std::to_string(data_growth) +
        ",\"process_io_delta\":" + io_delta +
        ",\"retained_data_file_bytes\":" + std::to_string(new_stat.st_size) + ",\"old_data_file_bytes\":" + std::to_string(old_data_bytes) +
        ",\"rr_occurrences\":" + std::to_string(snapshot.occurrences) + ",\"unique_rrs\":" + std::to_string(snapshot.unique_records) +
        ",\"parse_run_seconds\":" + std::to_string(parse_seconds) + ",\"order_interval_seconds\":" + std::to_string(order_seconds) +
        ",\"reencode_seconds\":" + std::to_string(encode_seconds) + ",\"publish_seconds\":" + std::to_string(publish_seconds) +
        ",\"total_seconds\":" + std::to_string(seconds_since(total_start)) + ",\"self_hwm_kib\":" + std::to_string(usage.ru_maxrss) + "}";
    if (!options.get("stats").empty()) {
        std::ofstream stats(options.get("stats"));
        require(stats.good(), "open update stats output");
        stats << summary << '\n';
        stats.close();
        require(stats.good(), "write update stats failed");
    }
    std::cerr << "SUMMARY " << summary << '\n';
    return 0;
}

int inspect_command(const Options& options) {
    Image image(options.need("image"));
    uint64_t committed = image.header().index_offset + final_index_bytes(image.header());
    std::cout << "{\"format\":\"ZIMDNS1\",\"origin\":" << json_string(name_text(image.origin()))
              << ",\"data_file\":" << json_string(image.data_path().string())
              << ",\"committed_data_bytes\":" << committed
              << ",\"actual_data_bytes\":" << fs::file_size(image.data_path())
              << ",\"index_offset\":" << image.header().index_offset
              << ",\"page_count\":" << image.header().page_count
              << ",\"index_bytes\":" << (image.header().flags & kCowIndexFlag ? image.cow_meta().created_node_bytes : final_index_bytes(image.header()))
              << ",\"index_format\":" << json_string(image.header().flags & kCowIndexFlag ? "cow" :
                                                         (image.header().flags & kPackedIndexFlag ? "packed" : "fixed"))
              << ",\"key_codec\":" << json_string(image.header().flags & kCompactKeyFlag ? "compact" : "nibble")
              << ",\"nsec3_next_key\":" << (image.header().flags & kNsec3NextKeyFlag ? "true" : "false")
              << ",\"rr_occurrences\":" << image.header().occurrences
              << ",\"unique_rrs\":" << image.header().unique_records
              << ",\"flags\":" << image.header().flags << ",\"cow_root\":";
    if (image.header().flags & kCowIndexFlag) {
        CowRef root = image.cow_root();
        std::cout << "{\"offset\":" << root.offset << ",\"length\":" << root.length << ",\"height\":" << root.height
                  << ",\"pages\":" << root.pages << ",\"checksum\":" << root.checksum << '}';
    } else std::cout << "null";
    std::cout << ",\"index_check\":";
    if (options.get("check-index", "0") == "1" && (image.header().flags & kCowIndexFlag)) {
        CowCheck result = image.check_cow_tree();
        std::cout << "{\"status\":\"PASS\",\"verified_nodes\":" << result.nodes << ",\"verified_leaves\":" << result.leaves
                  << ",\"reachable_node_bytes\":" << result.bytes << ",\"maximum_height\":" << result.maximum_height
                  << ",\"maximum_balance\":" << result.maximum_balance << '}';
    } else std::cout << "null";
    std::cout << ",\"dependencies\":[{\"path\":" << json_string(image.data_path().string())
              << ",\"committed_bytes\":" << committed << "}]}\n";
    return 0;
}

int dump_command(const Options& options, bool wire_only) {
    Image image(options.need("image"));
    image.each([&](const Record& record) {
        std::string wire = record_wire(record, image.origin(), nullptr, image.header().flags);
        std::string rendered;
        if (wire_only) rendered = hex(wire) + '\n';
        else {
            ldns_rr* rr = nullptr;
            size_t position = 0;
            ldns_status status = ldns_wire2rr(&rr, reinterpret_cast<const uint8_t*>(wire.data()), wire.size(),
                                            &position, LDNS_SECTION_ANSWER);
            require(status == LDNS_STATUS_OK && rr != nullptr && position == wire.size(), "stored RR wire invalid");
            char* text = ldns_rr2str(rr);
            require(text != nullptr, "stored RR text conversion failed");
            rendered = text;
            std::free(text);
            ldns_rr_free(rr);
        }
        for (uint64_t i = 0; i < record.multiplicity; ++i) std::cout << rendered;
    });
    require(std::cout.good(), "RR export write failed");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const uint16_t endian = 1;
        require(*reinterpret_cast<const uint8_t*>(&endian) == 1, "format v1 requires little-endian host");
        Options options = parse_options(argc, argv);
        if (options.command == "build") return build_command(options);
        if (options.command == "update") return update_command(options);
        if (options.command == "inspect") return inspect_command(options);
        if (options.command == "query" || options.command == "lookup" || options.command == "getrrset") return query_command(options);
        if (options.command == "wire") return dump_command(options, true);
        if (options.command == "dump") return dump_command(options, false);
        if (options.command == "canonical") {
            std::string origin = name_wire(options.need("origin"));
            read_zone(options.need("zone"), options.need("origin"), [&](const std::string& wire) {
                record_from_wire(wire, origin);
                std::cout << hex(wire) << '\n';
            });
            require(std::cout.good(), "canonical stream write failed");
            return 0;
        }
        throw std::runtime_error("unknown command " + options.command);
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << '\n';
        return 1;
    }
}
