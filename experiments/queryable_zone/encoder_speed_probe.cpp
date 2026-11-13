#define main zimdb_core_main
#include "native_zone.cpp"
#undef main

// Deterministic component experiment, never a source-to-image T_build result.
int main(int argc,char**argv){
    try{
        require(argc==3,"usage: encoder_speed_probe image sample_pages");
        Image image(argv[1]);
        uint64_t count=std::min<uint64_t>(std::stoull(argv[2]),image.header().page_count);
        require(count>0,"empty sample");
        uint32_t flags=image.header().flags|kRrsetPageFlag|kCowIndexFlag|kColumnPageFlag|kNsTemplateFlag|kNsec3PageLinkFlag|kNsPoolFlag;
        NsPoolBuilder pool(65536);
        SHA256_CTX hash;SHA256_Init(&hash);
        double decode_seconds=0,encode_seconds=0;
        uint64_t bytes=0,rows=0;
        for(uint64_t j=0;j<count;++j){
            uint64_t page=j*image.header().page_count/count;
            auto t=Clock::now();auto records=image.page(page);decode_seconds+=seconds_since(t);
            t=Clock::now();auto encoded=encode_page(records,false,true,flags,&pool);encode_seconds+=seconds_since(t);
            SHA256_Update(&hash,encoded.data(),encoded.size());
            bytes+=encoded.size();rows+=records.size();
        }
        FILE*temp=std::tmpfile();syscheck(temp,"probe pool temp");
        auto t=Clock::now();auto meta=pool.write(temp);double pool_seconds=seconds_since(t);
        syscheck(std::fflush(temp)==0,"flush probe pool");
        syscheck(std::fseek(temp,0,SEEK_SET)==0,"seek probe pool");
        std::array<unsigned char,65536>buffer{};
        for(size_t n;(n=std::fread(buffer.data(),1,buffer.size(),temp));)SHA256_Update(&hash,buffer.data(),n);
        require(!std::ferror(temp),"read probe pool");std::fclose(temp);
        unsigned char digest[32];SHA256_Final(digest,&hash);
        std::ostringstream hex;hex<<std::hex<<std::setfill('0');for(auto b:digest)hex<<std::setw(2)<<unsigned(b);
        rusage usage{};getrusage(RUSAGE_SELF,&usage);
        std::cout<<"{\"status\":\"COMPONENT_ONLY_PENDING_COMPARISON\",\"scope\":\"stratified increasing page sample; encode time excludes input decoding and hashing; not T_build\","
          <<"\"context\":"<<ZIMDB_GROUP_NS_CONTEXT<<",\"view_index\":"<<ZIMDB_VIEW_INTERN
          <<",\"source_pages\":"<<image.header().page_count<<",\"sample_pages\":"<<count<<",\"unique_rrs\":"<<rows
          <<",\"decode_seconds\":"<<decode_seconds<<",\"encode_seconds_not_T_build\":"<<encode_seconds
          <<",\"pool_write_seconds\":"<<pool_seconds<<",\"component_bytes\":"<<bytes
          <<",\"pool_bytes\":"<<meta.stored_bytes<<",\"component_sha256\":"<<json_string(hex.str())
          <<",\"child_peak_RSS_KiB\":"<<usage.ru_maxrss<<"}\n";
    }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
}
