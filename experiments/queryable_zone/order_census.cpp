#define main zimdb_core_main
#include "native_zone.cpp"
#undef main

int main(int argc, char** argv) {
    try {
        require(argc == 3, "usage: order_census flattened.zone origin");
        const auto start = Clock::now();
        std::string origin = name_wire(argv[2]);
        FILE* file = std::fopen(argv[1], "rb");
        syscheck(file, "open census source");
        std::setvbuf(file, nullptr, _IOFBF, 1<<20);
        char* line = nullptr;
        size_t capacity = 0;
        uint64_t rows = 0, changes = 0, descents = 0, run_rows = 0, max_run = 0;
        uint64_t escaped_rows = 0, literal_suffix_outside = 0;
        std::array<uint64_t, 64> histogram{};
        std::string previous_owner, previous_key;
        while (ssize_t length = ::getline(&line, &capacity, file)) {
            if (length < 0) break;
            size_t end = 0;
            while (end < size_t(length) && line[end] != '\t' && line[end] != ' ' && line[end] != '\r' && line[end] != '\n') ++end;
            if (!end || line[0] == ';') continue;
            require(line[0] != '$' && line[end-1] == '.', "requires flattened absolute-owner source");
            std::string owner(line, end);
            ++rows;
            if (owner.find('\\') != std::string::npos) ++escaped_rows;
            if (owner != previous_owner) {
                std::string key = make_key(name_wire(owner), origin, kCompactKeyFlag);
                ++changes;
                if (!previous_owner.empty() && byte_less(key, previous_key)) {
                    ++descents;
                    max_run = std::max(max_run, run_rows);
                    unsigned log = 0;
                    for (uint64_t n = run_rows; n >>= 1;) ++log;
                    ++histogram[log];
                    run_rows = 0;
                }
                previous_key = std::move(key);
                previous_owner = std::move(owner);
            }
            ++run_rows;
        }
        require(!std::ferror(file), "source read error");
        std::free(line);
        std::fclose(file);
        if (run_rows) {
            max_run = std::max(max_run, run_rows);
            unsigned log = 0;
            for (uint64_t n = run_rows; n >>= 1;) ++log;
            ++histogram[log];
        }
        std::cout << "{\"status\":\"PASS_ORDER_CENSUS_ONLY\",\"rows\":" << rows
                  << ",\"owner_transitions\":" << changes << ",\"owner_key_descents\":" << descents
                  << ",\"natural_owner_runs\":" << (rows ? descents+1 : 0)
                  << ",\"maximum_run_rows\":" << max_run << ",\"escaped_owner_rows\":" << escaped_rows
                  << ",\"seconds\":" << seconds_since(start) << ",\"run_length_log2_histogram\":[";
        for (size_t i = 0; i < histogram.size(); ++i) { if (i) std::cout << ','; std::cout << histogram[i]; }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
