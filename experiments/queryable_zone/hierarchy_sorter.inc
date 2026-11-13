// Selective order restoration. Verified monotone shallow-owner groups bypass
// global sorting. Arbitrarily disordered or deeper owners use bounded external
// sorting, followed by one exact merge with the monotone primary stream.
class HierarchyRunSorter : public NativeRunSorter {
public:
    HierarchyRunSorter(fs::path work, unsigned arena_mib, unsigned fan_in)
        : NativeRunSorter(work/"unused_base",1,fan_in), work_(std::move(work)),
          exceptions_(work_/"exceptions",arena_mib-2,fan_in),
          owner_(work_/"owner",1,fan_in) {
        require(arena_mib >= 3,"hierarchy sort needs at least 3 MiB of run workspace");
        fs::create_directories(work_/"exceptions");
        fs::create_directories(work_/"owner");
        primary_ = std::fopen((work_/"primary.bin").c_str(),"wb");
        syscheck(primary_,"create monotone primary run");
        std::setvbuf(primary_,nullptr,_IOFBF,65536);
    }
    ~HierarchyRunSorter() override { if (primary_) std::fclose(primary_); }

    void add(const std::string& key,std::string_view wire) override {
        if (!has_owner_ || key != current_owner_) {
            finish_current_owner();
            current_owner_ = key;
            has_owner_ = true;
            size_t labels = std::count(key.begin(),key.end(),'\0');
            primary_owner_ = labels <= 1 && (!has_primary_ || byte_less(last_primary_,key));
        }
        if (primary_owner_) {
            owner_.add(key,wire);
            ++primary_records_;
        } else {
            exceptions_.add(key,wire);
            ++exception_records_;
        }
    }
    void finish_runs() override {
        finish_current_owner();
        syscheck(std::fclose(primary_)==0,"close monotone primary run");
        primary_=nullptr;
        exceptions_.finish_runs();
    }
    void prepare_merges() override { exceptions_.prepare_merges(); }
    void final_merge(const std::function<void(const SortFrame&)>& consume) override {
        FILE* input = std::fopen((work_/"primary.bin").c_str(),"rb");
        syscheck(input,"open monotone primary run");
        std::setvbuf(input,nullptr,_IOFBF,65536);
        try {
            SortFrame current;
            bool has_current = read_sort_frame(input,current);
            uint64_t primary_seen = 0, exceptions_seen = 0;
            exceptions_.final_merge([&](const SortFrame& exception) {
                while (has_current && frame_less(current,exception)) {
                    consume(current);
                    ++primary_seen;
                    has_current = read_sort_frame(input,current);
                }
                consume(exception);
                ++exceptions_seen;
            });
            while (has_current) {
                consume(current);
                ++primary_seen;
                has_current = read_sort_frame(input,current);
            }
            require(primary_seen == primary_records_ && exceptions_seen == exception_records_,
                    "selective merge lost records");
            syscheck(std::fclose(input)==0,"close monotone primary input");
        } catch (...) { std::fclose(input); throw; }
    }
    double run_sort_write_seconds() const override {
        return exceptions_.run_sort_write_seconds()+owner_.run_sort_write_seconds()+owner_.memory_sort_seconds();
    }
    uint64_t initial_runs() const override { return (primary_records_?1:0)+exceptions_.initial_runs(); }
    uint64_t intermediate_passes() const override { return exceptions_.intermediate_passes(); }
    size_t arena_bytes() const override {
        return NativeRunSorter::arena_bytes()+exceptions_.arena_bytes()+owner_.arena_bytes();
    }
    size_t index_bytes() const override {
        return NativeRunSorter::index_bytes()+exceptions_.index_bytes()+owner_.index_bytes();
    }
    double memory_sort_seconds() const override {
        return exceptions_.memory_sort_seconds()+owner_.memory_sort_seconds();
    }
    uint64_t primary_records() const override { return primary_records_; }
    uint64_t exception_records() const override { return exception_records_; }
    uint64_t owner_spill_runs() const override { return owner_.initial_runs(); }
    uint64_t owner_spill_passes() const override { return owner_.intermediate_passes(); }

private:
    void finish_current_owner() {
        if (!has_owner_) return;
        if (primary_owner_) {
            owner_.finish_owner([&](const SortFrame& frame) {
                write_sort_frame(primary_,frame.key,frame.wire);
            });
            last_primary_=current_owner_;
            has_primary_=true;
        }
        has_owner_=false;
    }
    fs::path work_;
    NativeRunSorter exceptions_,owner_;
    FILE* primary_=nullptr;
    std::string current_owner_,last_primary_;
    bool has_owner_=false,has_primary_=false,primary_owner_=false;
    uint64_t primary_records_=0,exception_records_=0;
};
