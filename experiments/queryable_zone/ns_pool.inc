// Append-only bounded shared NS RR-multiset dictionary with independently
// compressed blocks. It is part of the image, never an external dependency.
#pragma pack(push,1)
struct NsPoolMeta {
    char magic[8];
    uint64_t directory_offset,entries,blocks,directory_checksum;
    uint64_t stored_bytes,raw_bytes,reserved;
};
struct NsPoolBlock {
    uint32_t first_id,count;
    uint64_t offset;
    uint32_t encoded_size,decoded_size,codec,reserved;
    uint64_t checksum;
};
#pragma pack(pop)
static_assert(sizeof(NsPoolMeta)==64 && sizeof(NsPoolBlock)==40,"NS pool layouts");
static_assert(sizeof(CowIndexMeta)+sizeof(NsPoolMeta)<=sizeof(ImageHeader::reserved),"pool header fits");

#ifndef ZIMDB_VIEW_INTERN
#define ZIMDB_VIEW_INTERN 0
#endif
#ifndef ZIMDB_POOL_FINGERPRINT_BITS
#define ZIMDB_POOL_FINGERPRINT_BITS 64
#endif
static_assert(ZIMDB_POOL_FINGERPRINT_BITS>=0&&ZIMDB_POOL_FINGERPRINT_BITS<=64,"pool fingerprint bit bound");

class NsPoolBuilder {
public:
    explicit NsPoolBuilder(uint32_t limit):limit_(limit) {
#if ZIMDB_VIEW_INTERN
        view_ids_.reserve(limit);
#else
        ids_.reserve(limit);
#endif
    }
    bool intern(const Bytes& bytes,uint32_t& id) {
#if ZIMDB_VIEW_INTERN
        return intern_span(std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size()),id,-1);
#else

        std::string identity(reinterpret_cast<const char*>(bytes.data()),bytes.size());
        auto found=ids_.find(identity);
        if(found!=ids_.end()){id=found->second;return true;}
        if(ids_.size()>=limit_ || bytes.size()>8*1024*1024-raw_)return false;
        id=entries_.size();raw_+=bytes.size();
        ids_.emplace(identity,id);entries_.push_back(std::move(identity));return true;
    #endif
    }
    bool intern_tagged(const Bytes& bytes,uint32_t& id,char tag) {
        require(tag=='S'||tag=='T',"invalid pool namespace");
#if ZIMDB_VIEW_INTERN
        return intern_span(std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size()),id,static_cast<unsigned char>(tag));
#else

        require(tag=='S'||tag=='T',"invalid pool namespace");
        Bytes tagged;tagged.reserve(bytes.size()+1);tagged.push_back(tag);
        tagged.insert(tagged.end(),bytes.begin(),bytes.end());
        std::string identity(reinterpret_cast<const char*>(tagged.data()),tagged.size());
        auto found=ids_.find(identity);
        if(found!=ids_.end()){id=found->second;return true;}
        size_t family=tag=='S'?0:1;
        if(tagged_counts_[family]>=limit_/2)return false;
        if(!intern(tagged,id))return false;
        ++tagged_counts_[family];return true;
    #endif
    }
    NsPoolMeta write(FILE* output)const {
        NsPoolMeta meta{};std::memcpy(meta.magic,"ZIMNSP1\0",8);
        meta.entries=entries_.size();meta.raw_bytes=raw_;
        std::vector<NsPoolBlock>directory;
        Bytes raw;uint32_t first=0,count=0;
        auto flush=[&]{
            if(!count)return;
            require(raw.size()<=kMaxPage,"NS pool block exceeds hard bound");
            Bytes compressed(ZSTD_compressBound(raw.size()));
            size_t n=ZSTD_compress(compressed.data(),compressed.size(),raw.data(),raw.size(),3);
            require(!ZSTD_isError(n),"NS pool compression failed");compressed.resize(n);
            bool use=compressed.size()<raw.size();const Bytes& stored=use?compressed:raw;
            off_t offset=::ftello(output);syscheck(offset>=0,"pool block offset");
            NsPoolBlock block{first,count,static_cast<uint64_t>(offset),static_cast<uint32_t>(stored.size()),
                static_cast<uint32_t>(raw.size()),use?2U:0U,0,checksum(raw.data(),raw.size())};
            write_all(output,stored.data(),stored.size());directory.push_back(block);
            meta.stored_bytes+=stored.size();first+=count;count=0;raw.clear();
        };
        for(const auto& entry:entries_){
            Bytes frame;put_varint(frame,entry.size());frame.insert(frame.end(),entry.begin(),entry.end());
            if(count&&raw.size()+frame.size()>65536)flush();
            raw.insert(raw.end(),frame.begin(),frame.end());++count;
        }
        flush();off_t offset=::ftello(output);syscheck(offset>=0,"pool directory offset");
        meta.directory_offset=offset;meta.blocks=directory.size();
        meta.directory_checksum=checksum(reinterpret_cast<const uint8_t*>(directory.data()),directory.size()*sizeof(NsPoolBlock));
        write_all(output,directory.data(),directory.size()*sizeof(NsPoolBlock));
        meta.stored_bytes+=directory.size()*sizeof(NsPoolBlock);
        return meta;
    }
private:
    uint32_t limit_;
    std::array<uint32_t,2>tagged_counts_{};
    uint64_t raw_=0;
#if ZIMDB_VIEW_INTERN
    std::unordered_multimap<uint64_t,uint32_t>view_ids_;
    bool intern_span(std::string_view bytes,uint32_t&id,int tag){
        uint64_t hash=14695981039346656037ULL;
        if(tag>=0){uint8_t byte=static_cast<uint8_t>(tag);hash=checksum_continue(hash,&byte,1);}
        hash=checksum_continue(hash,reinterpret_cast<const uint8_t*>(bytes.data()),bytes.size());
#if ZIMDB_POOL_FINGERPRINT_BITS < 64
        hash&=(uint64_t{1}<<ZIMDB_POOL_FINGERPRINT_BITS)-1;
#endif
        auto candidates=view_ids_.equal_range(hash);
        size_t prefix=tag>=0?1:0,required=bytes.size()+prefix;
        for(auto it=candidates.first;it!=candidates.second;++it){
            const auto&entry=entries_[it->second];
            if(entry.size()==required&&(!prefix||static_cast<unsigned char>(entry[0])==tag)&&
               (!bytes.size()||std::memcmp(entry.data()+prefix,bytes.data(),bytes.size())==0)){
                id=it->second;return true;
            }
        }
        size_t family=tag=='S'?0:1;
        if(prefix&&tagged_counts_[family]>=limit_/2)return false;
        if(entries_.size()>=limit_||required>8*1024*1024-raw_)return false;
        id=entries_.size();std::string entry;entry.reserve(required);
        if(prefix)entry.push_back(static_cast<char>(tag));
        entry.append(bytes.data(),bytes.size());
        raw_+=required;entries_.push_back(std::move(entry));view_ids_.emplace(hash,id);
        if(prefix)++tagged_counts_[family];
        return true;
    }
#else
    std::unordered_map<std::string,uint32_t>ids_;
#endif
    std::vector<std::string>entries_;
};

class NsPoolReader {
public:
    NsPoolReader(const uint8_t* data,uint64_t committed,const ImageHeader& header):data_(data),committed_(committed){
        std::memcpy(&meta_,header.reserved+sizeof(CowIndexMeta),sizeof(meta_));
        require(std::memcmp(meta_.magic,"ZIMNSP1\0",8)==0 && meta_.entries<=65536 &&
            meta_.blocks<=meta_.entries && meta_.raw_bytes<=8*1024*1024 &&
            meta_.directory_offset>=sizeof(ImageHeader) && meta_.directory_offset<=committed_ &&
            meta_.blocks<=(committed_-meta_.directory_offset)/sizeof(NsPoolBlock),"invalid NS pool header");
        auto* directory=data_+meta_.directory_offset;
        require(checksum(directory,meta_.blocks*sizeof(NsPoolBlock))==meta_.directory_checksum,"NS pool directory checksum");
        uint64_t next=0,stored=meta_.blocks*sizeof(NsPoolBlock);
        for(uint64_t i=0;i<meta_.blocks;++i){
            auto b=block(i);
            require(b.first_id==next && b.count && b.count<=meta_.entries-next &&
                b.offset>=sizeof(ImageHeader) && b.offset<=meta_.directory_offset &&
                b.encoded_size<=meta_.directory_offset-b.offset && b.decoded_size && b.decoded_size<=kMaxPage &&
                (b.codec==0||b.codec==2),"invalid NS pool block descriptor");
            next+=b.count;stored+=b.encoded_size;
        }
        require(next==meta_.entries && stored==meta_.stored_bytes,"NS pool accounting mismatch");
    }
    std::string lookup(uint32_t id)const {
        require(id<meta_.entries,"NS pool ID out of range");
        uint64_t lo=0,hi=meta_.blocks;
        while(lo+1<hi){uint64_t mid=lo+(hi-lo)/2;if(block(mid).first_id<=id)lo=mid;else hi=mid;}
        NsPoolBlock b=block(lo);
        require(id>=b.first_id && id-b.first_id<b.count,"NS pool ID gap");
        Cache& cache=cache_[lo%cache_.size()];
        if(cache.number!=lo){
            cache.raw.resize(b.decoded_size);
            if(b.codec==0){require(b.encoded_size==b.decoded_size,"raw NS block length");
                std::memcpy(cache.raw.data(),data_+b.offset,b.decoded_size);}
            else{size_t n=ZSTD_decompress(cache.raw.data(),cache.raw.size(),data_+b.offset,b.encoded_size);
                require(!ZSTD_isError(n)&&n==cache.raw.size(),"NS pool decompression failed");}
            require(checksum(cache.raw.data(),cache.raw.size())==b.checksum,"NS pool block checksum");
            cache.offsets.clear();cache.lengths.clear();cache.offsets.reserve(b.count);cache.lengths.reserve(b.count);
            size_t p=0;
            for(uint32_t i=0;i<b.count;++i){uint64_t length=get_varint(cache.raw.data(),cache.raw.size(),p);
                require(length&&length<=cache.raw.size()-p,"truncated NS pool definition");
                cache.offsets.push_back(p);cache.lengths.push_back(length);p+=length;}
            require(p==cache.raw.size(),"trailing NS pool bytes");cache.number=lo;
        }
        uint32_t rank=id-b.first_id;
        return std::string(reinterpret_cast<const char*>(cache.raw.data()+cache.offsets[rank]),cache.lengths[rank]);
    }
    const NsPoolMeta& meta()const{return meta_;}
private:
    NsPoolBlock block(uint64_t i)const {
        require(i<meta_.blocks,"NS block rank out of range");NsPoolBlock b{};
        std::memcpy(&b,data_+meta_.directory_offset+i*sizeof(b),sizeof(b));return b;
    }
    struct Cache{uint64_t number=UINT64_MAX;Bytes raw;std::vector<uint32_t>offsets,lengths;};
    const uint8_t*data_;uint64_t committed_;NsPoolMeta meta_{};
#ifndef ZIMDB_NS_POOL_CACHE_BLOCKS
#define ZIMDB_NS_POOL_CACHE_BLOCKS 16
#endif
    mutable std::array<Cache,ZIMDB_NS_POOL_CACHE_BLOCKS>cache_{};
};
