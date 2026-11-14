#include <openssl/evp.h>
#include <openssl/sha.h>
#include <zstd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <vector>

using Bytes = std::vector<unsigned char>;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::string digest_text(SHA256_CTX context) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &context);
    static const char* digits = "0123456789abcdef";
    std::string text(2 * sizeof(digest), '0');
    for (size_t i = 0; i < sizeof(digest); ++i) {
        text[2 * i] = digits[digest[i] >> 4];
        text[2 * i + 1] = digits[digest[i] & 15];
    }
    return text;
}

unsigned decimal(const char* text) {
    require(text && *text, "missing integer field");
    uint64_t value = 0;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
        require(*p >= '0' && *p <= '9', "non-decimal field");
        value = value * 10 + *p - '0';
        require(value <= UINT32_MAX, "integer field overflow");
    }
    return value;
}

size_t hex_length(const std::string& text) {
    require(text.size() % 2 == 0, "odd digest hex length");
    for (unsigned char c : text)
        require((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'),
                "invalid digest hex");
    return text.size() / 2;
}

size_t base32hex_length(const std::string& text) {
    require(!text.empty(), "empty NSEC3 hash");
    for (unsigned char c : text)
        require((c >= '0' && c <= '9') || (c >= 'A' && c <= 'V') || (c >= 'a' && c <= 'v'),
                "invalid base32hex hash");
    size_t bytes = text.size() * 5 / 8;
    require((bytes * 8 + 4) / 5 == text.size(), "noncanonical base32hex length");
    return bytes;
}

class SignatureCodec {
public:
    SignatureCodec() : pending_(1 << 20), encoded_(1 << 20), decoded_(1 << 20) {
        compression_ = ZSTD_createCStream();
        decompression_ = ZSTD_createDStream();
        require(compression_ && decompression_, "cannot create streaming codec");
        require(!ZSTD_isError(ZSTD_initCStream(compression_, 3)), "cannot initialize Zstd3");
        require(!ZSTD_isError(ZSTD_initDStream(decompression_)), "cannot initialize Zstd decoder");
        SHA256_Init(&raw_hash_);
        SHA256_Init(&decoded_hash_);
    }

    ~SignatureCodec() {
        ZSTD_freeCStream(compression_);
        ZSTD_freeDStream(decompression_);
    }

    void add(const unsigned char* data, size_t length) {
        raw_bytes += length;
        while (length) {
            size_t take = std::min(length, pending_.size() - pending_size_);
            std::memcpy(pending_.data() + pending_size_, data, take);
            pending_size_ += take;
            data += take;
            length -= take;
            if (pending_size_ == pending_.size()) flush_pending();
        }
    }

    void finish() {
        flush_pending();
        ZSTD_inBuffer input{nullptr, 0, 0};
        size_t remaining;
        do {
            ZSTD_outBuffer output{encoded_.data(), encoded_.size(), 0};
            remaining = ZSTD_compressStream2(compression_, &output, &input, ZSTD_e_end);
            require(!ZSTD_isError(remaining), "Zstd finish failed");
            consume_encoded(output.pos);
        } while (remaining);
        require(last_decode_result_ == 0 && decoded_bytes == raw_bytes, "streaming roundtrip length mismatch");
        require(digest_text(raw_hash_) == digest_text(decoded_hash_), "streaming roundtrip hash mismatch");
    }

    std::string raw_sha256() const { return digest_text(raw_hash_); }
    uint64_t raw_bytes = 0;
    uint64_t compressed_bytes = 0;
    uint64_t decoded_bytes = 0;

private:
    void flush_pending() {
        if (!pending_size_) return;
        SHA256_Update(&raw_hash_, pending_.data(), pending_size_);
        ZSTD_inBuffer input{pending_.data(), pending_size_, 0};
        while (input.pos < input.size) {
            ZSTD_outBuffer output{encoded_.data(), encoded_.size(), 0};
            size_t result = ZSTD_compressStream2(compression_, &output, &input, ZSTD_e_continue);
            require(!ZSTD_isError(result), "Zstd compression failed");
            consume_encoded(output.pos);
        }
        pending_size_ = 0;
    }

    void consume_encoded(size_t length) {
        compressed_bytes += length;
        ZSTD_inBuffer input{encoded_.data(), length, 0};
        size_t produced;
        do {
            ZSTD_outBuffer output{decoded_.data(), decoded_.size(), 0};
            last_decode_result_ = ZSTD_decompressStream(decompression_, &output, &input);
            require(!ZSTD_isError(last_decode_result_), "Zstd streaming decode failed");
            SHA256_Update(&decoded_hash_, decoded_.data(), output.pos);
            decoded_bytes += output.pos;
            produced = output.pos;
        } while (last_decode_result_ != 0 && (input.pos < input.size || produced == decoded_.size()));
    }

    ZSTD_CStream* compression_ = nullptr;
    ZSTD_DStream* decompression_ = nullptr;
    Bytes pending_, encoded_, decoded_;
    size_t pending_size_ = 0;
    size_t last_decode_result_ = 1;
    SHA256_CTX raw_hash_{}, decoded_hash_{};
};

struct Census {
    uint64_t records = 0;
    uint64_t signature_records = 0;
    uint64_t ds_records = 0;
    uint64_t ds_digest_bytes = 0;
    uint64_t nsec3_records = 0;
    uint64_t nsec3_owner_hash_bytes = 0;
    uint64_t nsec3_next_hash_bytes = 0;
    std::map<std::string, uint64_t> types;
    std::map<std::pair<unsigned, size_t>, uint64_t> signature_lengths;
    std::map<std::pair<unsigned, size_t>, uint64_t> ds_lengths;
    std::map<unsigned, uint64_t> nsec3_algorithms;
    SignatureCodec signatures;

    void line(char* text) {
        char* state = nullptr;
        auto next = [&]() { return ::strtok_r(nullptr, " \t\r\n", &state); };
        char* owner = ::strtok_r(text, " \t\r\n", &state);
        if (!owner) return;
        require(owner[0] != ';' && owner[0] != '$', "census requires flattened CZDS RR lines");
        decimal(next());
        char* klass = next();
        char* type = next();
        require(klass && ::strcasecmp(klass, "IN") == 0 && type, "unsupported flattened CZDS layout");
        for (char* p = type; *p; ++p) *p = static_cast<char>(std::toupper(static_cast<unsigned char>(*p)));
        ++records;
        ++types[type];
        if (std::strcmp(type, "RRSIG") == 0) {
            require(next(), "missing RRSIG covered type");
            unsigned algorithm = decimal(next());
            require(algorithm <= 255, "RRSIG algorithm overflow");
            for (unsigned i = 0; i < 6; ++i) require(next(), "missing RRSIG header field");
            std::string base64;
            for (char* part = next(); part; part = next()) base64 += part;
            require(!base64.empty() && base64.size() % 4 == 0 && base64.size() <= 90000,
                    "invalid signature base64 length");
            Bytes decoded(base64.size() / 4 * 3);
            int length = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(base64.data()), base64.size());
            require(length >= 0, "invalid signature base64");
            if (base64.back() == '=') --length;
            if (base64.size() > 1 && base64[base64.size() - 2] == '=') --length;
            require(length > 0, "empty signature payload");
            ++signature_records;
            ++signature_lengths[{algorithm, static_cast<size_t>(length)}];
            signatures.add(decoded.data(), length);
        } else if (std::strcmp(type, "DS") == 0) {
            decimal(next());
            decimal(next());
            unsigned digest_type = decimal(next());
            require(digest_type <= 255, "DS digest type overflow");
            std::string digest;
            for (char* part = next(); part; part = next()) digest += part;
            size_t length = hex_length(digest);
            require(length > 0, "empty DS digest");
            ++ds_records;
            ds_digest_bytes += length;
            ++ds_lengths[{digest_type, length}];
        } else if (std::strcmp(type, "NSEC3") == 0) {
            unsigned algorithm = decimal(next());
            require(algorithm <= 255, "NSEC3 algorithm overflow");
            decimal(next());
            decimal(next());
            require(next(), "missing NSEC3 salt");
            char* next_hash = next();
            require(next_hash, "missing NSEC3 next hash");
            const char* dot = std::strchr(owner, '.');
            require(dot && dot != owner, "invalid NSEC3 owner hash label");
            nsec3_owner_hash_bytes += base32hex_length(std::string(owner, dot - owner));
            nsec3_next_hash_bytes += base32hex_length(next_hash);
            ++nsec3_records;
            ++nsec3_algorithms[algorithm];
        }
    }
};

int main(int argc, char** argv) {
    try {
        require(argc == 3, "usage: com_payload_census SOURCE OUTPUT_JSON");
        const auto start = std::chrono::steady_clock::now();
        FILE* input = std::fopen(argv[1], "rb");
        require(input, "cannot open source");
        struct stat before{}, after{};
        require(::fstat(::fileno(input), &before) == 0, "cannot stat source");
        Census census;
        SHA256_CTX source_hash;
        SHA256_Init(&source_hash);
        Bytes buffer(8 << 20);
        std::string carry;
        uint64_t bytes = 0;
        while (size_t length = std::fread(buffer.data(), 1, buffer.size(), input)) {
            SHA256_Update(&source_hash, buffer.data(), length);
            bytes += length;
            char* cursor = reinterpret_cast<char*>(buffer.data());
            char* end = cursor + length;
            while (cursor < end) {
                char* newline = static_cast<char*>(std::memchr(cursor, '\n', end - cursor));
                if (!newline) {
                    carry.append(cursor, end - cursor);
                    require(carry.size() <= (1 << 20), "source line exceeds census bound");
                    break;
                }
                *newline = 0;
                if (carry.empty()) census.line(cursor);
                else {
                    carry.append(cursor, newline - cursor);
                    require(carry.size() <= (1 << 20), "source line exceeds census bound");
                    census.line(carry.data());
                    carry.clear();
                }
                cursor = newline + 1;
            }
        }
        require(!std::ferror(input), "source read error");
        if (!carry.empty()) census.line(carry.data());
        require(::fstat(::fileno(input), &after) == 0, "cannot restat source");
        std::fclose(input);
        require(before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
                before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && bytes == static_cast<uint64_t>(before.st_size),
                "source changed during scan");
        census.signatures.finish();
        struct rusage usage{};
        ::getrusage(RUSAGE_SELF, &usage);
        std::ofstream output(argv[2]);
        require(output.good(), "cannot open aggregate output");
        output << "{\n\"status\":\"PASS_FULL_SOURCE_CENSUS\",\n\"source\":\"" << argv[1]
               << "\",\n\"source_bytes\":" << bytes << ",\n\"source_sha256\":\"" << digest_text(source_hash)
               << "\",\n\"mtime_seconds\":" << before.st_mtim.tv_sec << ",\n\"mtime_nanoseconds\":" << before.st_mtim.tv_nsec
               << ",\n\"rr_occurrences\":" << census.records << ",\n\"types\":{";
        bool comma = false;
        for (const auto& item : census.types) {
            if (comma) output << ',';
            comma = true;
            output << '"' << item.first << "\":" << item.second;
        }
        output << "},\n\"rrsig_records\":" << census.signature_records
               << ",\n\"signature_decoded_bytes\":" << census.signatures.raw_bytes
               << ",\n\"signature_concat_sha256\":\"" << census.signatures.raw_sha256()
               << "\",\n\"signature_zstd3_stream_bytes\":" << census.signatures.compressed_bytes
               << ",\n\"signature_zstd3_stream_roundtrip\":true,\n\"signature_algorithm_lengths\":[";
        comma = false;
        for (const auto& item : census.signature_lengths) {
            if (comma) output << ',';
            comma = true;
            output << "{\"algorithm\":" << item.first.first << ",\"decoded_bytes\":" << item.first.second
                   << ",\"records\":" << item.second << '}';
        }
        output << "],\n\"ds_records\":" << census.ds_records << ",\n\"ds_digest_bytes\":" << census.ds_digest_bytes
               << ",\n\"ds_digest_lengths\":[";
        comma = false;
        for (const auto& item : census.ds_lengths) {
            if (comma) output << ',';
            comma = true;
            output << "{\"digest_type\":" << item.first.first << ",\"decoded_bytes\":" << item.first.second
                   << ",\"records\":" << item.second << '}';
        }
        output << "],\n\"nsec3_records\":" << census.nsec3_records
               << ",\n\"nsec3_owner_hash_bytes\":" << census.nsec3_owner_hash_bytes
               << ",\n\"nsec3_next_hash_bytes\":" << census.nsec3_next_hash_bytes
               << ",\n\"nsec3_algorithms\":{";
        comma = false;
        for (const auto& item : census.nsec3_algorithms) {
            if (comma) output << ',';
            comma = true;
            output << '"' << item.first << "\":" << item.second;
        }
        output << "},\n\"elapsed_seconds\":"
               << std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count()
               << ",\n\"self_peak_rss_kib\":" << usage.ru_maxrss
               << ",\n\"source_parser_scope\":\"flattened absolute-owner decimal-TTL IN TYPE RR lines; complete source bytes hashed; no global signature uniqueness claim\""
               << ",\n\"compression_scope\":\"all decoded signatures in source order; one Zstd3 stream; online decompression length/SHA256 verified; no payload files\"\n}\n";
        output.close();
        require(output.good(), "aggregate output write failed");
        std::cout << "census completed, aggregate output " << argv[2] << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "census error: " << error.what() << '\n';
        return 1;
    }
}
