#define main zimdb_core_main
#include "native_zone.cpp"
#undef main
#include <unordered_map>

class Component {
public:
    explicit Component(std::string name):name_(std::move(name)) {
        c_=ZSTD_createCCtx();d_=ZSTD_createDCtx();
        require(c_&&d_,"component contexts");
        require(!ZSTD_isError(ZSTD_CCtx_setParameter(c_,ZSTD_c_compressionLevel,3)),"component zstd level");
        input_.reserve(65536);
    }
    ~Component(){ ZSTD_freeCCtx(c_);ZSTD_freeDCtx(d_); }
    void add(const void* data,size_t bytes) {
        const uint8_t* ptr=static_cast<const uint8_t*>(data);
        while(bytes) {
            size_t n=std::min(bytes,65536-input_.size());
            input_.insert(input_.end(),ptr,ptr+n);ptr+=n;bytes-=n;
            if(input_.size()==65536)flush(false);
        }
    }
    void add(const Bytes& bytes){add(bytes.data(),bytes.size());}
    void add(const std::string& bytes){add(bytes.data(),bytes.size());}
    void finish() {
        flush(true);
        require(in_hash_==out_hash_&&raw_==decoded_,"component roundtrip mismatch");
    }
    void print()const {
        std::cout<<"{\"name\":"<<json_string(name_)<<",\"raw_bytes\":"<<raw_
                 <<",\"zstd3_stream_bytes\":"<<encoded_<<",\"roundtrip_checksum_verified\":true}";
    }
    uint64_t encoded()const{return encoded_;}
private:
    void flush(bool end) {
        raw_+=input_.size();
        in_hash_=checksum_continue(in_hash_,input_.data(),input_.size());
        ZSTD_inBuffer in{input_.data(),input_.size(),0};
        size_t more=1;
        do {
            ZSTD_outBuffer out{compressed_.data(),compressed_.size(),0};
            more=ZSTD_compressStream2(c_,&out,&in,end?ZSTD_e_end:ZSTD_e_continue);
            require(!ZSTD_isError(more),"component compression");
            encoded_+=out.pos;
            ZSTD_inBuffer encoded{compressed_.data(),out.pos,0};
            while(encoded.pos<encoded.size) {
                ZSTD_outBuffer decoded{decoded_buffer_.data(),decoded_buffer_.size(),0};
                size_t status=ZSTD_decompressStream(d_,&decoded,&encoded);
                require(!ZSTD_isError(status),"component decompression");
                decoded_+=decoded.pos;
                out_hash_=checksum_continue(out_hash_,decoded_buffer_.data(),decoded.pos);
            }
        }while(in.pos<in.size||(end&&more));
        input_.clear();
    }
    std::string name_;
    ZSTD_CCtx*c_=nullptr;ZSTD_DCtx*d_=nullptr;
    Bytes input_;
    std::array<uint8_t,131072>compressed_{},decoded_buffer_{};
    uint64_t raw_=0,encoded_=0,decoded_=0;
    uint64_t in_hash_=14695981039346656037ULL,out_hash_=14695981039346656037ULL;
};

int main(int argc,char**argv){
    try{
        require(argc==2,"usage: component_probe image");
        auto start=Clock::now();Image image(argv[1]);
        Component names("frontcoded_owner_groups"), refs("ns_set_ids_and_non_ns_counts"),
          definitions("bounded_ns_set_dictionary"), meta("non_ns_metadata_and_lengths"),
          residual("non_ns_residual_payload"), signatures("opaque_rrsig_signatures"),digests("opaque_ds_digests");
        std::unordered_map<std::string,uint32_t> dictionary;
        dictionary.reserve(65536);
        uint64_t dict_bytes=0,groups=0,ns_occurrences=0,reference_hits=0,literal_sets=0,sig_bytes=0;
        std::string previous;
        for(uint64_t page=0;page<image.header().page_count;++page){
            auto records=image.page(page);
            for(size_t first=0;first<records.size();){
                size_t last=first+1;while(last<records.size()&&records[last].key==records[first].key)++last;
                const std::string&key=records[first].key;
                size_t common=0;while(common<key.size()&&common<previous.size()&&key[common]==previous[common])++common;
                Bytes bytes;put_varint(bytes,common);put_varint(bytes,key.size()-common);
                bytes.insert(bytes.end(),key.begin()+common,key.end());names.add(bytes);previous=key;
                Bytes ns;uint64_t ns_count=0,non_ns=0;
                for(size_t i=first;i<last;++i){
                    const auto&r=records[i];
                    if(r.type!=2){++non_ns;continue;}
                    ++ns_count;ns_occurrences+=r.multiplicity;
                    put16(ns,r.klass);put32(ns,r.ttl);put_varint(ns,r.multiplicity);
                    put_varint(ns,r.rdata.size());ns.insert(ns.end(),r.rdata.begin(),r.rdata.end());
                }
                bytes.clear();
                if(!ns_count)put_varint(bytes,0);
                else{
                    Bytes blob;put_varint(blob,ns_count);blob.insert(blob.end(),ns.begin(),ns.end());
                    std::string identity(reinterpret_cast<const char*>(blob.data()),blob.size());
                    auto found=dictionary.find(identity);
                    if(found==dictionary.end()&&dictionary.size()<65536&&dict_bytes+identity.size()<=16*1024*1024){
                        uint32_t id=dictionary.size();dict_bytes+=identity.size();
                        found=dictionary.emplace(std::move(identity),id).first;
                        Bytes definition;put_varint(definition,blob.size());definition.insert(definition.end(),blob.begin(),blob.end());
                        definitions.add(definition);
                    }
                    if(found!=dictionary.end()){put_varint(bytes,found->second+2);++reference_hits;}
                    else{put_varint(bytes,1);put_varint(bytes,blob.size());bytes.insert(bytes.end(),blob.begin(),blob.end());++literal_sets;}
                }
                put_varint(bytes,non_ns);refs.add(bytes);
                for(size_t i=first;i<last;++i){
                    const auto&r=records[i];if(r.type==2)continue;
                    Bytes fields;put16(fields,r.type);put16(fields,r.klass);put32(fields,r.ttl);put_varint(fields,r.multiplicity);
                    put_varint(fields,r.rdata.size());
                    if(r.type==46){
                        require(r.rdata.size()>=19,"short signature RDATA");
                        size_t prefix=18+wire_name_length(reinterpret_cast<const uint8_t*>(r.rdata.data()+18),r.rdata.size()-18);
                        require(prefix<=r.rdata.size(),"bad signature prefix");
                        put_varint(fields,prefix);fields.insert(fields.end(),r.rdata.begin(),r.rdata.begin()+prefix);
                        signatures.add(r.rdata.data()+prefix,r.rdata.size()-prefix);sig_bytes+=r.rdata.size()-prefix;
                    }else if(r.type==43){
                        require(r.rdata.size()>=4,"short DS RDATA");
                        fields.insert(fields.end(),r.rdata.begin(),r.rdata.begin()+4);
                        digests.add(r.rdata.data()+4,r.rdata.size()-4);
                    }else residual.add(r.rdata);
                    meta.add(fields);
                }
                ++groups;first=last;
            }
            if((page+1)%100000==0)stage("component_probe",seconds_since(start),"\"pages\":"+std::to_string(page+1));
        }
        std::array<Component*,7>components{&names,&refs,&definitions,&meta,&residual,&signatures,&digests};
        uint64_t total=0;for(auto*c:components){c->finish();total+=c->encoded();}
        std::cout<<"{\"status\":\"PASS_COMPONENT_SCREENING_ONLY\",\"scope\":\"continuous streams; no random-access directories or full-image claim; literal fallbacks counted\","
                 <<"\"owner_page_groups\":"<<groups<<",\"dictionary_entries\":"<<dictionary.size()
                 <<",\"dictionary_raw_bytes\":"<<dict_bytes<<",\"ns_occurrences\":"<<ns_occurrences
                 <<",\"ns_reference_groups\":"<<reference_hits<<",\"ns_literal_groups\":"<<literal_sets
                 <<",\"signature_bytes\":"<<sig_bytes<<",\"sum_component_bytes\":"<<total
                 <<",\"seconds_not_T_build\":"<<seconds_since(start)<<",\"components\":[";
        for(size_t i=0;i<components.size();++i){if(i)std::cout<<',';components[i]->print();}
        std::cout<<"]}\n";
    }catch(const std::exception&e){std::cerr<<"ERROR "<<e.what()<<'\n';return 1;}
}
